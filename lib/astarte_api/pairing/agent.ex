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

defmodule Astarte.API.Pairing.Agent do
  @moduledoc """
  Astarte Pairing API used by agents. The `:auth_token` provided when creating the client for this module should be a JWT to access Pairing API.
  """

  defmodule Behaviour do
    # Behaviour module to help with tests
    @moduledoc false

    @callback register_device(
                client :: Astarte.API.client(),
                device_id :: String.t()
              ) :: Astarte.API.result()

    @callback unregister_device(
                client :: Astarte.API.client(),
                device_id :: String.t()
              ) ::
                Astarte.API.result()
  end

  @behaviour Astarte.API.Pairing.Agent.Behaviour

  @doc """
  Registers a device.

  `client` is a Pairing API client created with `Astarte.API.Pairing.client/3`.

  `device_id` is a valid Astarte device id, you can create a random one with `:crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)`

  ## Return values
    * `{:ok, result}` if the HTTP request can be performed. `result` will be a map with `status`, `headers` and `body`.
    * `{:error, reason}` if the HTTP request can't be performed.
  """
  @spec register_device(client :: Astarte.API.client(), device_id :: String.t()) ::
          Astarte.API.result()
  def register_device(client, device_id) do
    url = "/agent/devices"
    body = %{data: %{hw_id: device_id}}

    Astarte.API.post(client, url, body)
  end

  @doc """
  Unregisters a device.
   This makes it possible to register it again, even if it already has requested its credentials.
   All data belonging to the device will be kept as is.

  `client` is a Pairing API client created with `Astarte.API.Pairing.client/3`.

  `device_id` is the device id of a registered Astarte device.`

  ## Return values
    * `{:ok, result}` if the HTTP request can be performed. `result` will be a map with `status`, `headers` and `body`.
    * `{:error, reason}` if the HTTP request can't be performed.
  """
  @spec unregister_device(client :: Astarte.API.client(), device_id :: String.t()) ::
          Astarte.API.result()
  def unregister_device(client, device_id) do
    url = "/agent/devices/#{device_id}"

    Astarte.API.delete(client, url)
  end
end
