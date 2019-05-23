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

defmodule Astarte.Device.CredentialStorage do
  @moduledoc """
  User defined credential storage.

  `Astarte.Device.CredentialStorage` defines a behaviour that can be given to an `Astarte.Device`. This allows the user to specify how device credentials are stored.
  """

  @typedoc """
  Supported credential keys. You can pattern match on these if you want to store them each in a different way.
  """
  @type credential ::
          :private_key
          | :csr
          | :certificate

  @doc """

  """
  @callback init(args :: term()) :: {:ok, state :: term()}

  @doc """
  Save the specified credential to the credential storage.
  """
  @callback save(key :: credential(), value :: term(), state :: term()) ::
              {:ok, new_state :: term()}
              | {:error, reason :: term()}

  @doc """
  Fetch the specified credential from the credential storage.
  """
  @callback fetch(key :: credential(), state :: term()) ::
              {:ok, credential :: term()}
              | :error

  defmacro __using__(_args) do
    quote do
      @behaviour Astarte.Device.CredentialStorage

      @doc """
      Returns `true` if the credential storage contains `:private_key` and `:csr`, `false` otherwise.
      """
      def has_keypair?(state) do
        with {:ok, _private_key} <- fetch(:private_key, state),
             {:ok, _csr} <- fetch(:csr, state) do
          true
        else
          _ ->
            false
        end
      end

      @doc """
      Returns `true` if the credential storage contains `:certificate`, `false` otherwise.
      """
      def has_certificate?(state) do
        case fetch(:certificate, state) do
          {:ok, _certificate} -> true
          :error -> false
        end
      end
    end
  end
end
