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

defmodule Astarte.API.Pairing.Devices do
  @moduledoc """
  Astarte Pairing API used by devices. The `:auth_token` provided when creating the client for this module should be the credentials secret of the device.
  """

  @doc """
  Get the transports info for a device.

  `client` is a Pairing API client created with `Astarte.API.Pairing.client/3`.

  `device_id` is the device id of the device requesting its information.

  ## Return values
    * `{:ok, result}` if the HTTP request can be performed. `result` will be a map with `status`, `headers` and `body`.
    * `{:error, reason}` if the HTTP request can't be performed.
  """
  @spec info(client :: Astarte.API.client(), device_id :: String.t()) :: Astarte.API.result()
  def info(client, device_id) do
    url = "/devices/#{device_id}"

    Astarte.API.get(client, url)
  end

  @doc """
  Request credentials for the Astarte MQTT V1 protocol (i.e. an SSL client certificate).

  `client` is a Pairing API client created with `Astarte.API.Pairing.client/3`.

  `device_id` is the device id of the device requesting the certificate.

  `csr` is a PEM encoded certificate signing request.

  ## Return values
    * `{:ok, result}` if the HTTP request can be performed. `result` will be a map with `status`, `headers` and `body`.
    * `{:error, reason}` if the HTTP request can't be performed.
  """
  @spec get_mqtt_v1_credentials(
          client :: Astarte.API.client(),
          device_id :: String.t(),
          csr :: String.t()
        ) :: Astarte.API.result()
  def get_mqtt_v1_credentials(client, device_id, csr) do
    url = "/devices/#{device_id}/protocols/astarte_mqtt_v1/credentials"
    body = %{data: %{csr: csr}}

    Astarte.API.post(client, url, body)
  end

  @doc """
  Verify credentials for the Astarte MQTT V1 protocol (i.e. an SSL client certificate).

  `client` is a Pairing API client created with `Astarte.API.Pairing.client/3`.

  `device_id` is the device id of the device requesting the certificate.

  `certificate` is the PEM encoded certificate to be verified.

  ## Return values
    * `{:ok, result}` if the HTTP request can be performed. `result` will be a map with `status`, `headers` and `body`.
    * `{:error, reason}` if the HTTP request can't be performed.
  """
  @spec verify_mqtt_v1_credentials(
          client :: Astarte.API.client(),
          device_id :: String.t(),
          certificate :: String.t()
        ) :: Astarte.API.result()
  def verify_mqtt_v1_credentials(client, device_id, certificate) do
    url = "/devices/#{device_id}/protocols/astarte_mqtt_v1/credentials/verify"
    body = %{data: %{client_crt: certificate}}

    Astarte.API.post(client, url, body)
  end
end
