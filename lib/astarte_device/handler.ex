#
# This file is part of Astarte.
#
# Copyright 2019-2023 SECO Mind Srl
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

defmodule Astarte.Device.Handler do
  @moduledoc """
  This module defines a behaviour for handling incoming messages directed to an `Astarte.Device`.

  Modules implementing this behaviour will be executed in a separate process, to avoid blocking the MQTT
  connection process.
  """

  @doc """
  Initialize the state that will be passed as second argument to `handle_message/2`.

  If this function returns `{:error, reason}`, the handler process is stopped with reason `reason`.
  """
  @callback init_state(args :: term()) :: {:ok, state :: term()} | {:error, reason :: term()}

  @doc """
  Handle incoming data from Astarte.

  `message` is an `%Astarte.Device.Handler.Message{}`, which contains the following keys:
    * `realm` - the realm of the device.
    * `device_id` - the device id of the device.
    * `interface_name` - the interface name of the incoming message.
    * `path_tokens` - the path of the incoming message, split in a list of tokens (e.g. `String.split(path, "/", trim: true)`).
    * `value` - the value contained in the incoming message, already decoded to a standard Elixir type.
    * `timestamp` - if present, the timestamp contained in the incoming message, nil otherwise

  `state` is the current state of the handler.

  It's possible to return an updated state that will be passed to next `handle_message/2` calls.
  """
  @callback handle_message(message :: Astarte.Device.Handler.Message.t(), state :: term()) ::
              {:ok, new_state :: term()} | {:error, reason :: term()}

  defmacro __using__(_args) do
    quote location: :keep do
      use GenServer

      require Logger

      @doc """
      Starts the Handler process.
      """
      @spec start_link(args :: term) :: GenServer.on_start()
      def start_link(args) do
        GenServer.start_link(__MODULE__, args)
      end

      @impl true
      def init(args) do
        user_args = Keyword.fetch!(args, :user_args)
        realm = Keyword.fetch!(args, :realm)
        device_id = Keyword.fetch!(args, :device_id)

        case init_state(user_args) do
          {:ok, user_state} ->
            state = %{
              realm: realm,
              device_id: device_id,
              user_state: user_state
            }

            {:ok, state}

          {:error, reason} ->
            {:stop, reason}
        end
      end

      @impl true
      def handle_cast({:msg, interface_name, path_tokens, value, timestamp}, state) do
        alias Astarte.Device.Handler.Message

        %{
          realm: realm,
          device_id: device_id,
          user_state: user_state
        } = state

        message = %Message{
          realm: realm,
          device_id: device_id,
          interface_name: interface_name,
          path_tokens: path_tokens,
          value: value,
          timestamp: timestamp
        }

        new_state =
          with {:ok, new_user_state} <- handle_message(message, user_state) do
            %{state | user_state: new_user_state}
          else
            {:error, reason} ->
              _ =
                Logger.warning("#{realm}/#{device_id}: error handling message #{inspect(reason)}")

              state
          end

        {:noreply, new_state}
      end
    end
  end
end
