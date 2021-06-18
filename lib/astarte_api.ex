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

defmodule Astarte.API do
  @moduledoc false

  @type client :: Tesla.Client.t()
  @type client_option ::
          {:auth_token, String.t()}
  @type client_options :: [client_option]
  @type result :: {:ok, map()} | {:error, term()}

  @spec client(base_url :: String.t(), opts :: Astarte.API.client_options()) ::
          Astarte.API.client()
  def client(base_url, opts) do
    max_redirects = Keyword.get(opts, :max_redirects, 5)

    base_middlewares = [
      {Tesla.Middleware.BaseUrl, base_url},
      {Tesla.Middleware.JSON, []},
      {Tesla.Middleware.Timeout, timeout: 25_000},
      {Tesla.Middleware.FollowRedirects, max_redirects: max_redirects}
    ]

    middlewares =
      base_middlewares
      |> put_auth(opts)

    Tesla.client(middlewares)
  end

  defp put_auth(middlewares, opts) do
    case Keyword.fetch(opts, :auth_token) do
      {:ok, token} ->
        [{Tesla.Middleware.Headers, [{"Authorization", "Bearer: #{token}"}]} | middlewares]

      :error ->
        middlewares
    end
  end

  @spec get(client :: Astarte.API.client(), url :: String.t()) :: Astarte.API.result()
  def get(client, url) do
    Tesla.get(client, url)
    |> to_map()
  end

  @spec post(client :: Astarte.API.client(), url :: String.t(), body :: map()) ::
          Astarte.API.result()
  def post(client, url, body) do
    Tesla.post(client, url, body)
    |> to_map()
  end

  @spec delete(client :: Astarte.API.client(), url :: String.t()) ::
          Astarte.API.result()
  def delete(client, url) do
    Tesla.delete(client, url)
    |> to_map()
  end

  @spec to_map(Tesla.Env.result()) :: Astarte.API.result()
  defp to_map({:ok, %Tesla.Env{status: status, headers: headers, body: body}}) do
    {:ok, %{status: status, headers: headers, body: body}}
  end

  defp to_map(error) do
    error
  end
end
