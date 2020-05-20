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

defmodule Astarte.Device.TortoiseConnection do
  @moduledoc false

  @behaviour Astarte.Device.Connection

  @impl true
  def start_link(args) do
    with {:ok, broker_url} <- Keyword.fetch(args, :broker_url),
         {:ok, client_id} <- Keyword.fetch(args, :client_id),
         {:ok, key_pem} <- Keyword.fetch(args, :key_pem),
         {:key, {:ok, key}} <- {:key, X509.PrivateKey.from_pem(key_pem)},
         {:ok, certificate_pem} <- Keyword.fetch(args, :certificate_pem),
         {:cert, {:ok, certificate}} <- {:cert, X509.Certificate.from_pem(certificate_pem)} do
      initial_subscriptions = Keyword.get(args, :initial_subscriptions, [])
      ignore_ssl_errors = Keyword.get(args, :ignore_ssl_errors, false)

      %URI{
        host: broker_host,
        port: broker_port
      } = URI.parse(broker_url)

      verify = if ignore_ssl_errors, do: :verify_none, else: :verify_peer

      der_private_key = X509.PrivateKey.to_der(key)

      der_certificate = X509.Certificate.to_der(certificate)

      server_opts = [
        host: broker_host,
        port: broker_port,
        cacertfile: :certifi.cacertfile(),
        key: {:RSAPrivateKey, der_private_key},
        cert: der_certificate,
        depth: 10,
        verify: verify
      ]

      subscriptions = adapt_subscription_topics(initial_subscriptions)

      tortoise_opts = [
        client_id: client_id,
        handler: {Astarte.Device.TortoiseHandler, device_pid: self()},
        server: {Tortoise.Transport.SSL, server_opts},
        subscriptions: subscriptions
      ]

      Tortoise.Connection.start_link(tortoise_opts)
    else
      :error ->
        {:error, :invalid_args}

      {:key, _} ->
        {:error, :invalid_private_key}

      {:cert, _} ->
        {:error, :invalid_certificate}
    end
  end

  @impl true
  def subscribe_sync(client_id, topics) do
    subscriptions = adapt_subscription_topics(topics)
    Tortoise.Connection.subscribe_sync(client_id, subscriptions)
  end

  defp adapt_subscription_topics(topics) do
    for topic <- topics do
      {topic, 2}
    end
  end

  @impl true
  defdelegate publish_sync(client_id, topic, payload, opts \\ []), to: Tortoise
end
