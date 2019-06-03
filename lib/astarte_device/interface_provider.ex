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

defmodule Astarte.Device.InterfaceProvider do
  @moduledoc """
  This behaviour is used to implement a flexible way to retrieve interfaces for `Astarte.Device`.
  """

  @type state :: %{optional(String.t()) => %Astarte.Core.Interface{}}

  @doc """
  Initialize the `InterfaceProvider` and return its state.

  The state must be a map with the interface names as keys and the interfaces (as `%Astarte.Core.Interface{}` structs) as values.

  The callback can also return `{:error, reason}` if its fails.
  """
  @callback init(args :: term()) :: {:ok, state :: InterfaceProvider.state()} | {:error, reason :: term()}

  defmacro __using__(_opts) do
    alias Astarte.Core.Interface

    quote do
      @behaviour Astarte.Device.InterfaceProvider

      @doc """
      Get the list of all interfaces in the provider.
      """
      @spec all_interfaces(state :: InterfaceProvider.state()) :: [%Astarte.Core.Interface{}]
      def all_interfaces(state) when is_map(state) do
        Map.values(state)
      end

      @doc """
      Returns the interface with name `name` by calling `all_interfaces/1` and filtering the result.
      Get the interface by its name.

      Returns `{:ok, %Interface{}}` if the interface is found, `:error` if it's not.
      """
      @spec fetch_interface(name :: String.t(), state :: InterfaceProvider.state()) ::
              {:ok, %Astarte.Core.Interface{}} | :not_found
      def fetch_interface(name, state) when is_binary(name) and is_map(state) do
        Map.fetch(name, state)
      end

      @doc """
      Get the list of all device owned interfaces in the provider.
      """
      @spec device_owned_interfaces(state :: InterfaceProvider.state()) ::
              [%Astarte.Core.Interface{}]
      def device_owned_interfaces(state) when is_map(state) do
        for {_name, %Interface{ownership: :device} = interface} <- state do
          interface
        end
      end

      @doc """
      Get the list of all server owned interfaces in the provider.
      """
      @spec server_owned_interfaces(state :: InterfaceProvider.state()) ::
              [%Astarte.Core.Interface{}]
      def server_owned_interfaces(state) when is_map(state) do
        for {_name, %Interface{ownership: :server} = interface} <- state do
          interface
        end
      end
    end
  end
end
