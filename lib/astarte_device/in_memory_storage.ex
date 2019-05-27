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

defmodule Astarte.Device.InMemoryStorage do
  @moduledoc """
  A simple implementation of the `Astarte.Device.CredentialStorage` behaviour as an in-memory map.

  Note that using this the device will regenerate its credentials and request a new certificate every time since they're not persisted to disk.
  """

  use Astarte.Device.CredentialStorage

  @doc """
  Initializes the empty map.
  """
  @impl true
  def init(_args) do
    {:ok, %{}}
  end

  @doc """
  Stores the credential in the map.
  """
  @impl true
  def save(key, value, state) do
    {:ok, Map.put(state, key, value)}
  end

  @doc """
  Returns the credential from the map.
  """
  @impl true
  def fetch(key, state) do
    Map.fetch(state, key)
  end
end
