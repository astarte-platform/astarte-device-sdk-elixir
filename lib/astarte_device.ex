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

defmodule Astarte.Device do
  @moduledoc """
  A process that manages a device connection to Astarte. See `Astarte.Device.start_link/1` for the options.
  """

  @behaviour :gen_statem

  require Logger
  alias Astarte.Core.Interface
  alias Astarte.Core.Mapping

  # 7 days
  @nearly_expired_seconds 7 * 24 * 60 * 60
  @key_size 4096

  defmodule Data do
    @moduledoc false

    defstruct [
      :pairing_url,
      :realm,
      :device_id,
      :client_id,
      :credentials_secret,
      :broker_url,
      :mqtt_connection,
      :ignore_ssl_errors,
      :credential_storage_mod,
      :credential_storage_state,
      :interface_provider_mod,
      :interface_provider_state
    ]
  end

  # API

  @doc """
  Start an `Astarte.Device`.

  ## Device Options
    * `pairing_url` - URL of the Astarte Pairing API instance the device will connect to, up to (and including) `/v1`. E.g. `https://astarte.api.example.com/pairing/v1` or `http://localhost:4003/v1` for a local installation.
    * `realm` - Realm which the device belongs to.
    * `device_id` - Device ID of the device. The device ID must be 128-bit long and must be encoded with url-safe base64 without padding. You can generate a random one with `:crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)`.
    * `credentials_secret` - The credentials secret obtained when registering the device using Pairing API (to register a device use `Astarte.API.Pairing.Agent.register_device/2` or see https://docs.astarte-platform.org/latest/api/index.html?urls.primaryName=Pairing%20API#/agent/registerDevice).
    * `credential_storage` - A tuple `{module, args}` where `module` is a module implementing `Astarte.Device.CredentialStorage` behaviour and `args` are the arguments passed to its init function
    * `ignore_ssl_errors` - Defaults to `false`, if `true` the device will ignore SSL errors during connection. Useful if you're using the Device to connect to a test instance of Astarte with self signed certificates, it is not recommended to leave this `true` in production.
  """
  @spec start_link(device_options) :: :gen_statem.start_ret()
        when device_option:
               {:pairing_url, String.t()}
               | {:realm, String.t()}
               | {:device_id, String.t()}
               | {:credentials_secret, String.t()}
               | {:credential_storage, {module(), term()}}
               | {:interface_provider, {module(), term()}}
               | {:ignore_ssl_errors, boolean()},
             device_options: [device_option]
  def start_link(device_options) do
    pairing_url = Keyword.fetch!(device_options, :pairing_url)
    realm = Keyword.fetch!(device_options, :realm)
    device_id = Keyword.fetch!(device_options, :device_id)
    client_id = "#{realm}/#{device_id}"
    credentials_secret = Keyword.fetch!(device_options, :credentials_secret)
    ignore_ssl_errors = Keyword.get(device_options, :ignore_ssl_errors, false)

    {credential_storage_mod, credential_storage_args} =
      Keyword.fetch!(device_options, :credential_storage)

    {interface_provider_mod, interface_provider_args} =
      Keyword.fetch!(device_options, :interface_provider)

    with {:device_id, {:ok, _decoded_device_id}} <-
           {:device_id, Astarte.Core.Device.decode_device_id(device_id)},
         {:cred, {:ok, credential_storage_state}} <-
           {:cred, credential_storage_mod.init(credential_storage_args)},
         {:interface, {:ok, interface_provider_state}} <-
           {:interface, interface_provider_mod.init(interface_provider_args)} do
      data = %Data{
        pairing_url: pairing_url,
        realm: realm,
        device_id: device_id,
        client_id: client_id,
        credentials_secret: credentials_secret,
        ignore_ssl_errors: ignore_ssl_errors,
        credential_storage_mod: credential_storage_mod,
        credential_storage_state: credential_storage_state,
        interface_provider_mod: interface_provider_mod,
        interface_provider_state: interface_provider_state
      }

      :gen_statem.start_link(__MODULE__, data, [])
    else
      {:device_id, _} ->
        _ = Logger.warn("#{client_id}: Invalid device_id: #{device_id}")

        {:error, :invalid_device_id}

      {:cred, {:error, reason}} ->
        _ =
          Logger.warn(
            "#{client_id}: Can't initialize CredentialStorage for #{client_id}: #{inspect(reason)}"
          )

        {:error, :credential_storage_failed}

      {:interface, {:error, reason}} ->
        _ =
          Logger.warn(
            "#{client_id}: Can't initialize InterfaceProvider for #{client_id}: #{inspect(reason)}"
          )

        {:error, :interface_provider_failed}
    end
  end

  @doc """
  Send a datastream value to Astarte.

  This call is blocking and waits for the message to be ACKed at the MQTT level.
  """
  @spec send_datastream(
          pid :: pid(),
          interface_name :: String.t(),
          path :: String.t(),
          value :: term(),
          opts :: options
        ) ::
          :ok
          | {:error, reason :: term()}
        when options: [option],
             option: {:qos, qos :: Tortoise.qos()} | {:timestamp, timestamp :: DateTime.t()}
  def send_datastream(pid, interface_name, path, value, opts \\ []) do
    :gen_statem.call(pid, {:send_datastream, interface_name, path, value, opts})
  end

  @doc """
  Send a property value to Astarte.

  This call is blocking and waits for the message to be ACKed at the MQTT level.
  """
  @spec set_property(
          pid :: pid(),
          interface_name :: String.t(),
          path :: String.t(),
          value :: term()
        ) ::
          :ok
          | {:error, reason :: term()}
  def set_property(pid, interface_name, path, value) do
    :gen_statem.call(pid, {:set_property, interface_name, path, value})
  end

  # Callbacks

  @impl true
  def callback_mode, do: :state_functions

  @impl true
  def init(data) do
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
      actions = [{:next_event, :internal, :connect}]
      {:ok, :disconnected, data, actions}
    else
      {:keypair, false} ->
        actions = [{:next_event, :internal, :generate_keypair}]
        {:ok, :no_keypair, data, actions}

      {:certificate, :error} ->
        {:ok, :no_certificate, data}

      {:valid_certificate, false} ->
        # If the certificate is invalid, we treat it like it's not there
        {:ok, :no_certificate, data}

      {:error, reason} ->
        {:stop, reason}
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

  def no_keypair(:internal, :generate_keypair, data) do
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
           credential_storage_mod.save(
             :private_key,
             pem_private_key,
             credential_storage_state
           ),
         {:ok, with_key_and_csr_state} <-
           credential_storage_mod.save(:csr, pem_csr, with_key_state) do
      new_data = %{data | credential_storage_state: with_key_and_csr_state}
      actions = [{:next_event, :internal, :request_certificate}]

      {:next_state, :no_certificate, new_data, actions}
    else
      {:error, reason} ->
        # TODO: exponential backoff
        _ =
          Logger.warn(
            "#{client_id}: Failed to save keypair to credential storage: #{inspect(reason)}, trying again in 5 seconds"
          )

        actions = [{:state_timeout, 5000, :retry_generate_keypair}]
        {:keep_state_and_data, actions}
    end
  end

  def no_keypair(:state_timeout, :retry_generate_keypair, _data) do
    actions = [{:next_event, :internal, :generate_keypair}]
    {:keep_state_and_data, actions}
  end

  def no_keypair({:call, from}, _request, _data) do
    handle_disconnected_publish(from)
  end

  def no_certificate(:internal, :request_certificate, data) do
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

    client = Astarte.API.Pairing.client(pairing_url, realm, auth_token: credentials_secret)
    {:ok, csr} = credential_storage_mod.fetch(:csr, credential_storage_state)

    with {:api, {:ok, %{status: 201, body: body}}} <-
           {:api, Astarte.API.Pairing.Devices.get_mqtt_v1_credentials(client, device_id, csr)},
         %{"data" => %{"client_crt" => pem_certificate}} = body,
         {:store, {:ok, new_credential_storage_state}} <-
           {:store,
            credential_storage_mod.save(
              :certificate,
              pem_certificate,
              credential_storage_state
            )} do
      _ = Logger.info("#{client_id}: Received new certificate")
      new_data = %{data | credential_storage_state: new_credential_storage_state}
      actions = [{:next_event, :internal, :request_info}]
      {:next_state, :waiting_for_info, new_data, actions}
    else
      {:api, {:error, reason}} ->
        # HTTP request can't be made
        # TODO: exponential backoff
        _ =
          Logger.warn(
            "#{client_id}: Failed to ask for a certificate: #{inspect(reason)}. Trying again in 30 seconds"
          )

        actions = [{:state_timeout, 30_000, :retry_request_certificate}]
        {:keep_state_and_data, actions}

      {:api, {:ok, %{status: status, body: body}}} ->
        # HTTP request succeeded but returned an error status
        # TODO: pattern match on the status + exponential backoff
        _ =
          Logger.warn(
            "#{client_id}: Get credentials failed with status #{status}: #{inspect(body)}. Trying again in 30 seconds."
          )

        actions = [{:state_timeout, 30_000, :retry_request_certificate}]
        {:keep_state_and_data, actions}

      {:store, {:error, reason}} ->
        # TODO: exponential backoff
        _ =
          Logger.warn(
            "#{client_id}: Credential storage could not save certificate: #{inspect(reason)}. Trying again in 30 seconds."
          )

        actions = [{:state_timeout, 30_000, :retry_request_certificate}]
        {:keep_state_and_data, actions}
    end
  end

  def no_certificate(:state_timeout, :retry_request_certificate, _data) do
    actions = [{:next_event, :internal, :request_certificate}]
    {:keep_state_and_data, actions}
  end

  def no_certificate({:call, from}, _request, _data) do
    handle_disconnected_publish(from)
  end

  def waiting_for_info(:internal, :request_info, data) do
    %Data{
      client_id: client_id,
      credentials_secret: credentials_secret,
      pairing_url: pairing_url,
      realm: realm,
      device_id: device_id
    } = data

    _ = Logger.info("#{client_id}: Requesting info")

    client = Astarte.API.Pairing.client(pairing_url, realm, auth_token: credentials_secret)

    with {:ok, %{status: 200, body: body}} <- Astarte.API.Pairing.Devices.info(client, device_id),
         broker_url when not is_nil(broker_url) <-
           get_in(body, ["data", "protocols", "astarte_mqtt_v1", "broker_url"]) do
      _ = Logger.info("#{client_id}: Broker url is #{broker_url}")
      new_data = %{data | broker_url: broker_url}
      actions = [{:next_event, :internal, :connect}]
      {:next_state, :disconnected, new_data, actions}
    else
      {:error, reason} ->
        # HTTP request can't be made
        # TODO: exponential backoff
        _ =
          Logger.warn(
            "#{client_id}: Failed to obtain transport info: #{inspect(reason)}. Trying again in 30 seconds"
          )

        actions = [{:state_timeout, 30_000, :retry_request_info}]
        {:keep_state_and_data, actions}

      {:ok, %{status: status, body: body}} ->
        # HTTP request succeeded but returned an error status
        # TODO: pattern match on the status + exponential backoff
        _ =
          Logger.warn(
            "#{client_id}: Get info failed with status #{status}: #{inspect(body)}. Trying again in 30 seconds."
          )

        actions = [{:state_timeout, 30_000, :retry_request_info}]
        {:keep_state_and_data, actions}
    end
  end

  def waiting_for_info(:state_timeout, :retry_request_info, _data) do
    actions = [{:next_event, :internal, :request_info}]
    {:keep_state_and_data, actions}
  end

  def waiting_for_info({:call, from}, _request, _data) do
    handle_disconnected_publish(from)
  end

  def disconnected(:internal, :connect, data) do
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

      # TODO: trap exits to catch SSL errors, timeouts etc
      case Tortoise.Connection.start_link(tortoise_opts) do
        {:ok, pid} ->
          new_data = %{data | mqtt_connection: pid}
          {:next_state, :connecting, new_data}

        {:error, reason} ->
          _ =
            Logger.warn(
              "#{client_id}: failed to connect: #{inspect(reason)}. Trying again in 30 seconds."
            )

          # TODO: exponential backoff
          actions = [{:state_timeout, :retry_connect, 30_000}]
          {:keep_state_and_data, actions}
      end
    end
  end

  def disconnected(:state_timeout, :retry_connect, _data) do
    actions = [{:next_event, :internal, :connect}]
    {:keep_state_and_data, actions}
  end

  def disconnected({:call, from}, _request, _data) do
    handle_disconnected_publish(from)
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

  def connecting(:cast, {:connection_status, :up}, %Data{client_id: client_id} = data) do
    _ = Logger.info("#{client_id}: Connected")

    # TODO: we always send empty cache and producer properties for now since we can't access the session_present flag
    actions = [
      {:next_event, :internal, :send_introspection},
      {:next_event, :internal, :send_empty_cache},
      {:next_event, :internal, :send_producer_properties}
    ]

    {:next_state, :connected, data, actions}
  end

  def connecting({:call, from}, _request, _data) do
    handle_disconnected_publish(from)
  end

  def connected(:internal, :send_introspection, data) do
    %Data{
      client_id: client_id,
      interface_provider_mod: interface_provider_mod,
      interface_provider_state: interface_provider_state
    } = data

    interfaces = interface_provider_mod.all_interfaces(interface_provider_state)

    introspection = build_introspection(interfaces)

    _ = Logger.info("#{client_id}: Sending introspection: #{introspection}")

    # Introspection topic is the same as client_id
    topic = client_id
    :ok = Tortoise.publish_sync(client_id, topic, introspection, qos: 2)

    :keep_state_and_data
  end

  def connected(:internal, :send_empty_cache, data) do
    %Data{
      client_id: client_id
    } = data

    _ = Logger.info("#{client_id}: Sending empty cache")
    # TODO: send empty cache

    :keep_state_and_data
  end

  def connected(:internal, :send_producer_properties, data) do
    %Data{
      client_id: client_id
    } = data

    _ = Logger.info("#{client_id}: Sending producer properties")
    # TODO: build and send producer properties

    :keep_state_and_data
  end

  def connected(:cast, {:connection_status, :down}, %Data{client_id: client_id} = data) do
    # Tortoise will reconnect for us, just go to the :connecting state
    _ = Logger.info("#{client_id}: Disconnected. Retrying connection...")

    {:next_state, :connecting, data}
  end

  def connected({:call, from}, {:send_datastream, interface_name, path, value, opts}, data) do
    publish_params = %{
      publish_type: :datastream,
      interface_name: interface_name,
      path: path,
      value: value,
      opts: opts
    }

    reply = handle_publish(publish_params, data)
    actions = [{:reply, from, reply}]
    {:keep_state_and_data, actions}
  end

  def connected({:call, from}, {:set_property, interface_name, path, value}, data) do
    publish_params = %{
      publish_type: :properties,
      interface_name: interface_name,
      path: path,
      value: value,
      opts: [qos: 2]
    }

    reply = handle_publish(publish_params, data)
    actions = [{:reply, from, reply}]
    {:keep_state_and_data, actions}
  end

  def connected(_event_type, _event, _data) do
    :keep_state_and_data
  end

  defp handle_disconnected_publish(from) do
    actions = [{:reply, from, {:error, :device_disconnected}}]
    {:keep_state_and_data, actions}
  end

  defp handle_publish(publish_params, data) do
    %{
      publish_type: publish_type,
      interface_name: interface_name,
      path: path,
      value: value,
      opts: opts
    } = publish_params

    %Data{
      client_id: client_id,
      interface_provider_mod: interface_provider_mod,
      interface_provider_state: interface_provider_state
    } = data

    with {:ok, %Interface{type: ^publish_type} = interface} <-
           interface_provider_mod.fetch_interface(interface_name, interface_provider_state) do
      publish(client_id, interface, path, value, opts)
    else
      :error ->
        _ =
          Logger.warn(
            "#{client_id}: Trying to publish to not-existing interface #{interface_name}. Ignoring."
          )

        {:error, :interface_not_found}

      # We weren't expecting properties, so we came from send_datastream
      {:ok, %Interface{type: :properties}} ->
        _ =
          Logger.warn("#{client_id}: send_datastream on properties interface: #{interface_name}")

        {:error, :properties_interface}

      # We weren't expecting datastream, so we came from set_property
      {:ok, %Interface{type: :datastream}} ->
        _ = Logger.warn("#{client_id}: set_property on datastream interface: #{interface_name}")

        {:error, :properties_interface}
    end
  end

  defp publish(client_id, interface, path, value, opts) do
    # TODO:
    # - Handle empty payload (check allow_unset)
    # - Enforce timestamps if explicit_timestamp is true
    # - Check aggregation

    %Interface{
      name: interface_name
    } = interface

    with %Interface{ownership: :device, mappings: mappings} <- interface,
         {:ok, %Mapping{value_type: expected_type}} <- find_mapping(path, mappings),
         :ok <- Mapping.ValueType.validate_value(expected_type, value),
         payload_map = build_payload_map(value, opts),
         {:ok, bson_payload} <- Cyanide.encode(payload_map) do
      publish_opts = Keyword.take(opts, [:qos])

      topic = Path.join([client_id, interface_name, path])

      Tortoise.publish_sync(client_id, topic, bson_payload, publish_opts)
    else
      %Interface{ownership: :server} ->
        _ =
          Logger.warn(
            "#{client_id}: Trying to publish to server-owned interface #{interface_name}"
          )

        {:error, :server_owned_interface}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp find_mapping(path, mappings) do
    with {:ok, endpoint_automaton} <- Mapping.EndpointsAutomaton.build(mappings),
         {:ok, endpoint} <- Mapping.EndpointsAutomaton.resolve_path(path, endpoint_automaton),
         %Mapping{} = mapping <-
           Enum.find(mappings, fn %Mapping{} = mapping ->
             mapping.endpoint == endpoint
           end) do
      {:ok, mapping}
    else
      _ ->
        {:error, :cannot_resolve_path}
    end
  end

  defp build_payload_map(value, opts) do
    case Keyword.fetch(opts, :timestamp) do
      {:ok, %DateTime{} = timestamp} ->
        %{v: value, t: timestamp}

      _ ->
        %{v: value}
    end
  end

  defp build_introspection(interfaces) do
    for %Interface{name: interface_name, major_version: major, minor_version: minor} <- interfaces do
      "#{interface_name}:#{major}:#{minor}"
    end
    |> Enum.join(";")
  end
end
