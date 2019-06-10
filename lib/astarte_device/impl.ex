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

defmodule Astarte.Device.Impl do
  @moduledoc false

  alias Astarte.Device.Data

  # 7 days
  @nearly_expired_seconds 7 * 24 * 60 * 60

  @type data :: Astarte.Device.Data.t()

  @spec init(opts :: keyword()) ::
          {:ok, data :: data()}
          | {:no_keypair, data :: data()}
          | {:no_certificate, data :: data()}
  def init(opts) do
    data = Data.from_opts!(opts)

    %Data{
      credential_storage_mod: credential_storage_mod,
      credential_storage_state: credential_storage_state
    } = data

    with {:keypair, true} <-
           {:keypair, credential_storage_mod.has_keypair?(credential_storage_state)},
         {:certificate, {:ok, pem_certificate}} <-
           {:certificate, credential_storage_mod.fetch(:certificate, credential_storage_state)},
         {:valid_certificate, true} <-
           {:valid_certificate, valid_certificate?(pem_certificate)} do
      {:ok, data}
    else
      {:keypair, false} ->
        {:no_keypair, data}

      {:certificate, :error} ->
        {:no_certificate, data}

      {:valid_certificate, false} ->
        # If the certificate is invalid, we treat it like it's not there
        {:no_certificate, data}
    end
  end

  defp valid_certificate?(pem_certificate) do
    with {:ok, certificate} <- X509.Certificate.from_pem(pem_certificate) do
      {:Validity, _not_before, not_after} = X509.Certificate.validity(certificate)

      seconds_until_expiry =
        not_after
        |> X509.DateTime.to_datetime()
        |> DateTime.diff(DateTime.utc_now())

      # If the certificate it's near its expiration, we treat it as invalid
      seconds_until_expiry > @nearly_expired_seconds
    else
      {:error, _reason} ->
        false
    end
  end
end
