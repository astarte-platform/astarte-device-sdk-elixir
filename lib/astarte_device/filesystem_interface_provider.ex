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

defmodule Astarte.Device.FilesystemInterfaceProvider do
  use Astarte.Device.InterfaceProvider

  require Logger
  alias Astarte.Core.Interface

  @doc """
  Loads interfaces from a dir or a single JSON file.

  Returns `{:ok, interfaces}` where `interfaces` is a list of `%Astarte.Core.Interface{}`.

  `args` is a keyword list of options.

  ### Options

  * `path` - A filesystem path. This can be a single JSON file or a directory.
  If it's a directory, all files with a `.json` extension in the directory will
  be parsed as interfaces, otherwise the path is interpreted as a path to a single
  JSON file containing an interface.
  """
  @impl true
  def init(args) do
    path = Keyword.fetch!(args, :path)

    if File.dir?(path) do
      interfaces = load_interfaces_from_dir(path)
      {:ok, interfaces}
    else
      case load_interface_from_file(path) do
        {:ok, %Interface{name: interface_name} = interface} ->
          {:ok, %{interface_name => interface}}

        :error ->
          {:ok, []}
      end
    end
  end

  defp load_interfaces_from_dir(dir_path) do
    dir_path
    |> Path.join("*.json")
    |> Path.wildcard()
    |> Enum.reduce(%{}, fn file, acc ->
      with {:ok, %Interface{name: interface_name} = interface} <- load_interface_from_file(file) do
        Map.put(acc, interface_name, interface)
      else
        _ ->
          acc
      end
    end)
  end

  defp load_interface_from_file(file_path) do
    with {:ok, file_contents} <- File.read(file_path),
         {:ok, interface_params} <- Jason.decode(file_contents),
         interface_changeset = Interface.changeset(%Interface{}, interface_params),
         {:ok, %Interface{} = interface} <-
           Ecto.Changeset.apply_action(interface_changeset, :insert) do
      {:ok, interface}
    else
      {:error, %Ecto.Changeset{errors: errors}} ->
        _ = Logger.warn("Invalid interface #{file_path}: #{inspect(errors)}")
        :error

      {:error, reason} ->
        _ = Logger.warn("Problem loading interface #{file_path}: #{inspect(reason)}")
        :error
    end
  end
end
