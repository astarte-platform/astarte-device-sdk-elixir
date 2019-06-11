#
# This file is part of Astarte.
#
# Copyright 2019 Ispirata Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule Astarte.Device.Impl do
  @moduledoc false

  require Logger

  alias Astarte.Core.Interface
  alias Astarte.Device.Data

  # 7 days
  @nearly_expired_seconds 7 * 24 * 60 * 60
  @key_size 4096

  @type data :: Astarte.Device.Data.t()

  @spec init(opts :: keyword()) ::
          {:ok, data :: data()}
          | {:no_keypair, data :: data()}
          | {:no_certificate, data :: data()}
  def init(opts) do
    data = Data.from_opts!(opts)

    %Data{
      credential_storage_mod: credential_storage_mod,
      credential_storage_state: credential_storage_state
    } = data

    with {:keypair, true} <-
           {:keypair, credential_storage_mod.has_keypair?(credential_storage_state)},
         {:certificate, {:ok, pem_certificate}} <-
           {:certificate, credential_storage_mod.fetch(:certificate, credential_storage_state)},
         {:valid_certificate, true} <-
           {:valid_certificate, valid_certificate?(pem_certificate)} do
      {:ok, data}
    else
      {:keypair, false} ->
        {:no_keypair, data}

      {:certificate, :error} ->
        {:no_certificate, data}

      {:valid_certificate, false} ->
        # If the certificate is invalid, we treat it like it's not there
        {:no_certificate, data}
    end
  end

  defp valid_certificate?(pem_certificate) do
    with {:ok, certificate} <- X509.Certificate.from_pem(pem_certificate) do
      {:Validity, _not_before, not_after} = X509.Certificate.validity(certificate)

      seconds_until_expiry =
        not_after
        |> X509.DateTime.to_datetime()
        |> DateTime.diff(DateTime.utc_now())

      # If the certificate it's near its expiration, we treat it as invalid
      seconds_until_expiry > @nearly_expired_seconds
    else
      {:error, _reason} ->
        false
    end
  end

  @spec generate_keypair(data :: data()) ::
          {:ok, new_data :: data()}
          | {:error, reason :: term()}
  def generate_keypair(data) do
    %Data{
      client_id: client_id,
      credential_storage_mod: credential_storage_mod,
      credential_storage_state: credential_storage_state
    } = data

    _ = Logger.info("#{client_id}: Generating a new keypair")

    # TODO: make crypto configurable (RSA/EC, key size/curve)
    private_key = X509.PrivateKey.new_rsa(@key_size)

    pem_csr =
      private_key
      |> X509.CSR.new("CN=#{client_id}")
      |> X509.CSR.to_pem()

    pem_private_key = X509.PrivateKey.to_pem(private_key)

    with {:ok, with_key_state} <-
           credential_storage_mod.save(:private_key, pem_private_key, credential_storage_state),
         {:ok, with_key_and_csr_state} <-
           credential_storage_mod.save(:csr, pem_csr, with_key_state) do
      {:ok, %{data | credential_storage_state: with_key_and_csr_state}}
    end
  end

  @spec request_certificate(data :: data()) ::
          {:ok, new_data :: data()}
          | {:error, :temporary}
          | {:error, reason :: term()}
  def request_certificate(data) do
    alias Astarte.API.Pairing

    %Data{
      client_id: client_id,
      pairing_url: pairing_url,
      realm: realm,
      credentials_secret: credentials_secret,
      device_id: device_id,
      credential_storage_mod: credential_storage_mod,
      credential_storage_state: credential_storage_state
    } = data

    _ = Logger.info("#{client_id}: Requesting new certificate")

    client = Pairing.client(pairing_url, realm, auth_token: credentials_secret)
    {:ok, csr} = credential_storage_mod.fetch(:csr, credential_storage_state)

    with {:api, {:ok, %{status: 201, body: body}}} <-
           {:api, Pairing.Devices.get_mqtt_v1_credentials(client, device_id, csr)},
         %{"data" => %{"client_crt" => pem_cert}} = body,
         {:store, {:ok, new_credential_storage_state}} <-
           {:store, credential_storage_mod.save(:certificate, pem_cert, credential_storage_state)} do
      _ = Logger.info("#{client_id}: Received new certificate")
      {:ok, %{data | credential_storage_state: new_credential_storage_state}}
    else
      error ->
        classify_error(error, client_id)
    end
  end

  @spec request_info(data :: data()) ::
          {:ok, new_data :: data()}
          | {:error, :temporary}
          | {:error, reason :: term()}
  def request_info(data) do
    %Data{
      client_id: client_id,
      credentials_secret: credentials_secret,
      pairing_url: pairing_url,
      realm: realm,
      device_id: device_id
    } = data

    _ = Logger.info("#{client_id}: Requesting info")

    client = Astarte.API.Pairing.client(pairing_url, realm, auth_token: credentials_secret)

    with {:api, {:ok, %{status: 200, body: body}}} <-
           {:api, Astarte.API.Pairing.Devices.info(client, device_id)} do
      %{"data" => %{"protocols" => %{"astarte_mqtt_v1" => %{"broker_url" => broker_url}}}} = body
      _ = Logger.info("#{client_id}: Broker url is #{broker_url}")
      {:ok, %{data | broker_url: broker_url}}
    else
      error ->
        classify_error(error, client_id)
    end
  end

  @spec connect(data :: data()) ::
          {:ok, new_data :: data()}
          | {:error, reason :: term()}
  def connect(data) do
    %Data{
      client_id: client_id,
      broker_url: broker_url,
      ignore_ssl_errors: ignore_ssl_errors,
      credential_storage_mod: credential_storage_mod,
      credential_storage_state: credential_storage_state,
      interface_provider_mod: interface_provider_mod,
      interface_provider_state: interface_provider_state
    } = data

    %URI{
      host: broker_host,
      port: broker_port
    } = URI.parse(broker_url)

    verify = if ignore_ssl_errors, do: :verify_none, else: :verify_peer

    with {:ok, pem_private_key} <-
           credential_storage_mod.fetch(:private_key, credential_storage_state),
         {:ok, pem_certificate} <-
           credential_storage_mod.fetch(:certificate, credential_storage_state) do
      server_owned_interfaces =
        interface_provider_mod.server_owned_interfaces(interface_provider_state)

      der_certificate =
        pem_certificate
        |> X509.Certificate.from_pem!()
        |> X509.Certificate.to_der()

      der_private_key =
        pem_private_key
        |> X509.PrivateKey.from_pem!()
        |> X509.PrivateKey.to_der()

      server_opts = [
        host: broker_host,
        port: broker_port,
        cacertfile: :certifi.cacertfile(),
        key: {:RSAPrivateKey, der_private_key},
        cert: der_certificate,
        verify: verify
      ]

      subscriptions = build_subscriptions(client_id, server_owned_interfaces)

      tortoise_opts = [
        client_id: client_id,
        handler: {Astarte.Device.MqttHandler, device_pid: self()},
        server: {Tortoise.Transport.SSL, server_opts},
        subscriptions: subscriptions
      ]

      with {:ok, pid} <- Tortoise.Connection.start_link(tortoise_opts) do
        {:ok, %{data | mqtt_connection: pid}}
      end
    end
  end

  defp build_subscriptions(client_id, server_interfaces) do
    # Subscriptions are {topic_filter, qos} tuples
    control_topic_subscription = {"#{client_id}/control/#", 2}

    interface_topic_subscriptions =
      Enum.flat_map(server_interfaces, fn %Interface{name: interface_name} ->
        [{"#{client_id}/#{interface_name}", 2}, {"#{client_id}/#{interface_name}/#", 2}]
      end)

    [control_topic_subscription | interface_topic_subscriptions]
  end

  defp classify_error({:api, {:error, reason}}, log_tag)
       when reason in [:econnrefused, :closed] do
    # Temporary errors
    _ = Logger.warn("#{log_tag}: Temporary failure in API request: #{inspect(reason)}.")
    {:error, :temporary}
  end

  defp classify_error({:api, {:error, reason}}, log_tag) do
    # Other errors are assumed to be permanent
    _ = Logger.warn("#{log_tag}: Failure in API request: #{inspect(reason)}.")
    {:error, reason}
  end

  defp classify_error({:api, {:ok, %{status: status, body: body}}}, log_tag)
       when status >= 500 do
    # We assume Server Errors in the 500 range are temporary
    _ = Logger.warn("#{log_tag}: API request failed with status #{status}: #{inspect(body)}.")

    {:error, :temporary}
  end

  defp classify_error({:api, {:ok, %{status: status, body: body}}}, log_tag)
       when status >= 400 and status < 500 do
    # All HTTP errors in the 400 range are assumed to be permanent (authentication, bad request etc)
    _ = Logger.warn("#{log_tag}: API request failed with status #{status}: #{inspect(body)}.")

    {:error, :request_certificate_failed}
  end

  defp classify_error({:store, {:error, reason}}, log_tag) do
    # Storage errors are assumed to be permanent
    _ = Logger.warn("#{log_tag}: failed to store credentials")
    {:error, reason}
  end
end
