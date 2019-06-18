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
  alias Astarte.Device.Impl

  defmodule Data do
    @moduledoc false

    @type t :: %Astarte.Device.Data{
            pairing_url: String.t(),
            realm: String.t(),
            device_id: Astarte.Core.Device.encoded_device_id(),
            client_id: String.t(),
            credentials_secret: String.t(),
            ignore_ssl_errors: boolean(),
            credential_storage_mod: module(),
            credential_storage_state: term(),
            interface_provider_mod: module(),
            interface_provider_state: term(),
            handler_pid: pid(),
            broker_url: String.t() | nil,
            mqtt_connection: pid() | nil
          }

    @enforce_keys [
      :pairing_url,
      :realm,
      :device_id,
      :client_id,
      :credentials_secret,
      :ignore_ssl_errors,
      :credential_storage_mod,
      :credential_storage_state,
      :interface_provider_mod,
      :interface_provider_state,
      :handler_pid
    ]
    defstruct [
      :broker_url,
      :mqtt_connection
      | @enforce_keys
    ]

    def from_opts!(opts) do
      pairing_url = Keyword.fetch!(opts, :pairing_url)
      realm = Keyword.fetch!(opts, :realm)
      device_id = Keyword.fetch!(opts, :device_id)
      client_id = Keyword.fetch!(opts, :client_id)
      credentials_secret = Keyword.fetch!(opts, :credentials_secret)
      ignore_ssl_errors = Keyword.fetch!(opts, :ignore_ssl_errors)
      credential_storage_mod = Keyword.fetch!(opts, :credential_storage_mod)
      credential_storage_state = Keyword.fetch!(opts, :credential_storage_state)
      interface_provider_mod = Keyword.fetch!(opts, :interface_provider_mod)
      interface_provider_state = Keyword.fetch!(opts, :interface_provider_state)
      handler_pid = Keyword.fetch!(opts, :handler_pid)

      %Data{
        pairing_url: pairing_url,
        realm: realm,
        device_id: device_id,
        client_id: client_id,
        credentials_secret: credentials_secret,
        ignore_ssl_errors: ignore_ssl_errors,
        credential_storage_mod: credential_storage_mod,
        credential_storage_state: credential_storage_state,
        interface_provider_mod: interface_provider_mod,
        interface_provider_state: interface_provider_state,
        handler_pid: handler_pid
      }
    end
  end

  # API

  @type device_options :: [device_option]

  @type device_option ::
          {:pairing_url, String.t()}
          | {:realm, String.t()}
          | {:device_id, String.t()}
          | {:credentials_secret, String.t()}
          | {:credential_storage, {module(), term()}}
          | {:interface_provider, {module(), term()} | String.t()}
          | {:handler, {module(), term()}}
          | {:ignore_ssl_errors, boolean()}

  @doc """
  Start an `Astarte.Device`.

  ## Device Options
    * `pairing_url` - URL of the Astarte Pairing API instance the device will connect to, up to (and including) `/v1`. E.g. `https://astarte.api.example.com/pairing/v1` or `http://localhost:4003/v1` for a local installation.
    * `realm` - Realm which the device belongs to.
    * `device_id` - Device ID of the device. The device ID must be 128-bit long and must be encoded with url-safe base64 without padding. You can generate a random one with `:crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)`.
    * `credentials_secret` - The credentials secret obtained when registering the device using Pairing API (to register a device use `Astarte.API.Pairing.Agent.register_device/2` or see https://docs.astarte-platform.org/latest/api/index.html?urls.primaryName=Pairing%20API#/agent/registerDevice).
    * `interface_provider` - A tuple `{module, args}` where `module` is a module implementing `Astarte.Device.InterfaceProvider` behaviour and `args` are the arguments passed to its init function. It's also possible to pass a path containing the JSON interfaces the device will use, and that path will be passed to `Astarte.Device.FilesystemInterfaceProvider`.
    * `credential_storage` (optional) - A tuple `{module, args}` where `module` is a module implementing `Astarte.Device.CredentialStorage` behaviour and `args` are the arguments passed to its init function. If not provided, `Astarte.Device.InMemoryStorage` will be used.
    * `handler` (optional) - A tuple `{module, args}` where `module` is a module implementing `Astarte.Device.Handler` behaviour and `args` are the arguments passed to its `init_state` function. If not provided, `Astarte.Device.DefaultHandler` will be used.
    * `ignore_ssl_errors` (optional) - Defaults to `false`, if `true` the device will ignore SSL errors during connection. Useful if you're using the Device to connect to a test instance of Astarte with self signed certificates, it is not recommended to leave this `true` in production.
  """
  @spec start_link(opts :: device_options()) :: :gen_statem.start_ret()
  def start_link(device_options) do
    pairing_url = Keyword.fetch!(device_options, :pairing_url)
    realm = Keyword.fetch!(device_options, :realm)
    device_id = Keyword.fetch!(device_options, :device_id)
    client_id = "#{realm}/#{device_id}"
    credentials_secret = Keyword.fetch!(device_options, :credentials_secret)
    ignore_ssl_errors = Keyword.get(device_options, :ignore_ssl_errors, false)

    {credential_storage_mod, credential_storage_args} =
      Keyword.get(device_options, :credential_storage, {Astarte.Device.InMemoryStorage, []})

    {interface_provider_mod, interface_provider_args} =
      case Keyword.fetch!(device_options, :interface_provider) do
        {mod, args} when is_atom(mod) ->
          {mod, args}

        path when is_binary(path) ->
          {Astarte.Device.FilesystemInterfaceProvider, path: path}
      end

    {handler_mod, handler_args} =
      Keyword.get(device_options, :handler, {Astarte.Device.DefaultHandler, []})

    with {:device_id, {:ok, _decoded_device_id}} <-
           {:device_id, Astarte.Core.Device.decode_device_id(device_id)},
         {:cred, {:ok, credential_storage_state}} <-
           {:cred, credential_storage_mod.init(credential_storage_args)},
         {:interface, {:ok, interface_provider_state}} <-
           {:interface, interface_provider_mod.init(interface_provider_args)} do
      opts = [
        pairing_url: pairing_url,
        realm: realm,
        device_id: device_id,
        client_id: client_id,
        credentials_secret: credentials_secret,
        ignore_ssl_errors: ignore_ssl_errors,
        credential_storage_mod: credential_storage_mod,
        credential_storage_state: credential_storage_state,
        interface_provider_mod: interface_provider_mod,
        interface_provider_state: interface_provider_state,
        handler_mod: handler_mod,
        handler_args: handler_args
      ]

      :gen_statem.start_link(via_tuple(realm, device_id), __MODULE__, opts, [])
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
  Returns the `pid` of the `Astarte.Device` process for the given `realm/device_id` pair, or `nil` if
  there's no existing device for that pair.

  Devices are registered to `Astarte.Device.Registry` with key `{realm, device_id}` when they are started.
  """
  @spec get_pid(realm :: String.t(), device_id :: Astarte.Core.Device.encoded_device_id()) ::
          pid() | nil
  def get_pid(realm, device_id) do
    case Registry.lookup(Astarte.Device.Registry, {realm, device_id}) do
      [{pid, _}] ->
        pid

      _ ->
        nil
    end
  end

  @spec via_tuple(realm :: String.t(), device_id :: Astarte.Core.Device.encoded_device_id()) ::
          {:via, registry :: module(), via_name :: term()}
  defp via_tuple(realm, device_id) do
    {:via, Registry, {Astarte.Device.Registry, {realm, device_id}}}
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
  def init(opts) do
    realm = Keyword.fetch!(opts, :realm)
    device_id = Keyword.fetch!(opts, :device_id)
    handler_mod = Keyword.fetch!(opts, :handler_mod)
    handler_args = Keyword.fetch!(opts, :handler_args)

    handler_full_args = [
      realm: realm,
      device_id: device_id,
      user_args: handler_args
    ]

    # TODO: this should probably go in a supervision tree with the Device,
    # avoiding the need to peek in the options
    {:ok, handler_pid} = handler_mod.start_link(handler_full_args)

    new_opts = Keyword.put(opts, :handler_pid, handler_pid)

    case Impl.init(new_opts) do
      {:ok, new_data} ->
        actions = [{:next_event, :internal, :request_info}]
        {:ok, :waiting_for_info, new_data, actions}

      {:no_keypair, new_data} ->
        actions = [{:next_event, :internal, :generate_keypair}]
        {:ok, :no_keypair, new_data, actions}

      {:no_certificate, new_data} ->
        actions = [{:next_event, :internal, :request_certificate}]
        {:ok, :no_certificate, new_data, actions}
    end
  end

  def no_keypair(:internal, :generate_keypair, data) do
    case Impl.generate_keypair(data) do
      {:ok, new_data} ->
        actions = [{:next_event, :internal, :request_certificate}]
        {:next_state, :no_certificate, new_data, actions}

      {:error, reason} ->
        # TODO: handle transient errors, for now we stop if a keypair
        # can't be generated or saved
        {:stop, reason}
    end
  end

  def no_keypair({:call, from}, _request, _data) do
    handle_disconnected_publish(from)
  end

  def no_certificate(:internal, :request_certificate, data) do
    case Impl.request_certificate(data) do
      {:ok, new_data} ->
        actions = [{:next_event, :internal, :request_info}]
        {:next_state, :waiting_for_info, new_data, actions}

      {:error, :temporary} ->
        # TODO: exponential backoff
        actions = [{:state_timeout, 30_000, :retry_request_certificate}]
        _ = Logger.warn("Trying again in 30 seconds")
        {:keep_state_and_data, actions}

      {:error, reason} ->
        {:stop, reason}
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
    case Impl.request_info(data) do
      {:ok, new_data} ->
        actions = [{:next_event, :internal, :connect}]
        {:next_state, :disconnected, new_data, actions}

      {:error, :temporary} ->
        # TODO: exponential backoff
        actions = [{:state_timeout, 30_000, :retry_request_info}]
        _ = Logger.warn("Trying again in 30 seconds")
        {:keep_state_and_data, actions}

      {:error, reason} ->
        {:stop, reason}
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
    case Impl.connect(data) do
      {:ok, new_data} ->
        {:next_state, :connecting, new_data}

      {:error, reason} ->
        # The connection has its own retry mechanism, if we're here the error is fatal
        {:stop, reason}
    end
  end

  def disconnected(:state_timeout, :retry_connect, _data) do
    actions = [{:next_event, :internal, :connect}]
    {:keep_state_and_data, actions}
  end

  def disconnected({:call, from}, _request, _data) do
    handle_disconnected_publish(from)
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
    # TODO: handle errors
    :ok = Impl.send_introspection(data)

    :keep_state_and_data
  end

  def connected(:internal, :send_empty_cache, data) do
    # TODO: handle errors
    :ok = Impl.send_empty_cache(data)

    :keep_state_and_data
  end

  def connected(:internal, :send_producer_properties, data) do
    # TODO: handle errors
    :ok = Impl.send_producer_properties(data)

    :keep_state_and_data
  end

  def connected(:cast, {:connection_status, :down}, %Data{client_id: client_id} = data) do
    # Tortoise will reconnect for us, just go to the :connecting state
    _ = Logger.info("#{client_id}: Disconnected. Retrying connection...")

    {:next_state, :connecting, data}
  end

  def connected(:cast, {:msg, topic_tokens, payload}, data) do
    %Data{
      client_id: client_id
    } = data

    case Impl.handle_message(topic_tokens, payload, data) do
      :ok ->
        :keep_state_and_data

      {:ok, new_data} ->
        {:keep_state, new_data}

      {:error, reason} ->
        Logger.warn("#{client_id}: error in handle_message #{inspect(reason)}")
        :keep_state_and_data
    end
  end

  def connected({:call, from}, {:send_datastream, interface_name, path, value, opts}, data) do
    publish_params = [
      publish_type: :datastream,
      interface_name: interface_name,
      path: path,
      value: value,
      opts: opts
    ]

    reply = Impl.publish(publish_params, data)
    actions = [{:reply, from, reply}]
    {:keep_state_and_data, actions}
  end

  def connected({:call, from}, {:set_property, interface_name, path, value}, data) do
    publish_params = [
      publish_type: :properties,
      interface_name: interface_name,
      path: path,
      value: value,
      opts: [qos: 2]
    ]

    reply = Impl.publish(publish_params, data)
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
end
