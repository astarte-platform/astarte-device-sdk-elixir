#
# This file is part of Astarte.
#
# Copyright 2020-2023 SECO Mind Srl
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

defmodule Astarte.Device.SimpleInterfaceProvider do
  use Astarte.Device.InterfaceProvider

  require Logger
  alias Astarte.Core.Interface

  @doc """
  Loads interfaces from a list of maps, each representing the JSON serialization of an interface.

  Returns `{:ok, interfaces}` where `interfaces` is a map of `interface_name => %Astarte.Core.Interface{}`
  or `{:error, reason}` if an interface can't be loaded.

  `args` is a keyword list of options.

  ### Options

  * `interfaces` - A list of maps representing an interface.
  """
  @impl true
  def init(args) do
    interfaces = Keyword.fetch!(args, :interfaces)

    with {:ok, interfaces} <- load_interfaces(interfaces) do
      {:ok, interfaces}
    end
  end

  defp load_interfaces(interfaces) when is_list(interfaces) do
    Enum.reduce_while(interfaces, {:ok, %{}}, fn interface_map, {:ok, acc} ->
      case load_interface(interface_map) do
        {:ok, %Interface{name: interface_name} = interface} ->
          {:cont, {:ok, Map.put(acc, interface_name, interface)}}

        {:error, reason} ->
          {:halt, {:error, reason}}
      end
    end)
  end

  defp load_interface(interface_map) do
    interface_changeset = Interface.changeset(%Interface{}, interface_map)

    case Ecto.Changeset.apply_action(interface_changeset, :insert) do
      {:ok, %Interface{} = interface} ->
        {:ok, interface}

      {:error, %Ecto.Changeset{errors: errors}} ->
        _ = Logger.warning("Invalid interface map #{inspect(interface_map)}: #{inspect(errors)}")
        {:error, :invalid_interface}
    end
  end
end
