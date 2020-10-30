defmodule Astarte.DeviceTest do
  use ExUnit.Case
  import Mox

  alias Astarte.Device

  @pairing_url "http://localhost:4003"
  @realm "test"
  @device_id "FJrMBxtwTP2CTkqYUVmurw"
  @client_id "#{@realm}/#{@device_id}"
  @credentials_secret "12345"
  @interfaces_dir Path.expand("test/interfaces")
  @certificate """
  -----BEGIN CERTIFICATE-----
  MIIDYDCCAkigAwIBAgIJAJXCkuI7009FMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
  BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
  aWRnaXRzIFB0eSBMdGQwHhcNMTkwNjE0MDk0MjMzWhcNMjAwNjEzMDk0MjMzWjBF
  MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
  ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
  CgKCAQEAwUs5H6MrCBtLtpyiZcIQ0mz3cgS4mZIk1KjMZcWx5LoMT7BywjQqiHmZ
  xKz+p5Kmi43hoy/wDEpfY4KgCWPoGoUxitBVdCAaUWP6SPj+WDnVvl2uHBNDqp49
  ENZJwdX1cx4On6X0DcQMwH6sHkjv3kVS3lXrzIVvEXIn9QFEv9AxJymLMR9VDOyU
  F7vmwRCi07CGva4sAceY85P9WmLu5XOrt0FSsQzQmf2nL5ZpFjfTrt8tTN4axXKi
  Fop9KL0Xc7B4baWVIyxUJWw+MinQTvlwif9IP94Y6EOgO1H782DFG0BCq/q3W3KR
  HBhMthNqcjiiGtnVE29PqxVYEsc87wIDAQABo1MwUTAdBgNVHQ4EFgQUTHDT6pQ5
  I2oIAR9TNmP57QjEL4IwHwYDVR0jBBgwFoAUTHDT6pQ5I2oIAR9TNmP57QjEL4Iw
  DwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAjc0jh1f9+moyaaFo
  20/jhvkeSjS9+iD2RlCc2mxvvkRf2+ECQ+mY+MAXH37FJy9U4pPp5cz8x+kdKwYm
  VKYzvs6YCnZIyWo0ryxqIJscLZSsQF7uSxyp9n+UODdHtONe2PW1qAp+fXKHb6oT
  eEX3vXbggfG1RN13sK/jCG5wI8qrasEZcTVU+sv+KdLtq9e4jdQ9JPkEZNuGZoqU
  RktOI9Njy+a74pE17WD0XZKK81TcW6c0fPAkFiG61rHh41BLWfrn+60QsvaqMnWr
  ap9JZn1gjqddbwXBpHm/bojvkN/DcCGikxPFUQo3/lICDreo9J+E25iAXTut55Ue
  LAsZ1Q==
  -----END CERTIFICATE-----
  """

  describe "start_link/1" do
    setup :verify_on_exit!

    test "fails when required options are missing" do
      no_pairing_url = [
        realm: @realm,
        device_id: @device_id,
        credentials_secret: @credentials_secret,
        interface_provider: @interfaces_dir
      ]

      assert_raise KeyError, fn ->
        Device.start_link(no_pairing_url)
      end

      no_realm = [
        pairing_url: @pairing_url,
        device_id: @device_id,
        credentials_secret: @credentials_secret,
        interface_provider: @interfaces_dir
      ]

      assert_raise KeyError, fn ->
        Device.start_link(no_realm)
      end

      no_device_id = [
        pairing_url: @pairing_url,
        realm: @realm,
        credentials_secret: @credentials_secret,
        interface_provider: @interfaces_dir
      ]

      assert_raise KeyError, fn ->
        Device.start_link(no_device_id)
      end

      no_credentials_secret = [
        pairing_url: @pairing_url,
        realm: @realm,
        device_id: @device_id,
        interface_provider: @interfaces_dir
      ]

      assert_raise KeyError, fn ->
        Device.start_link(no_credentials_secret)
      end

      no_interface_provider = [
        pairing_url: @pairing_url,
        realm: @realm,
        device_id: "invalid",
        credentials_secret: @credentials_secret
      ]

      assert_raise KeyError, fn ->
        Device.start_link(no_interface_provider)
      end
    end

    test "fails when device id is invalid" do
      opts = [
        pairing_url: @pairing_url,
        realm: @realm,
        device_id: "invalid",
        credentials_secret: @credentials_secret,
        interface_provider: @interfaces_dir
      ]

      assert Device.start_link(opts) == {:error, :invalid_device_id}
    end

    test "fails when credential storage init fails" do
      CredentialStorageMock
      |> expect(:init, fn _ -> {:error, :master_of_failure} end)

      opts = [
        pairing_url: @pairing_url,
        realm: @realm,
        device_id: @device_id,
        credentials_secret: @credentials_secret,
        interface_provider: @interfaces_dir,
        credential_storage: {CredentialStorageMock, []}
      ]

      assert Device.start_link(opts) == {:error, :credential_storage_failed}
    end

    test "fails when interface provider init fails" do
      InterfaceProviderMock
      |> expect(:init, fn _ -> {:error, :master_of_failure} end)

      opts = [
        pairing_url: @pairing_url,
        realm: @realm,
        device_id: @device_id,
        credentials_secret: @credentials_secret,
        interface_provider: {InterfaceProviderMock, []}
      ]

      assert Device.start_link(opts) == {:error, :interface_provider_failed}
    end
  end

  describe "send_datastream" do
    setup [:set_mox_from_context, :verify_on_exit!, :init_device]

    test "fails on a property interface", %{device: device} do
      interface = "org.astarteplatform.test.DeviceProperties"
      path = "/intValue"
      value = 42

      :ok = wait_for_connection()

      assert Device.send_datastream(device, interface, path, value) ==
               {:error, :properties_interface}
    end

    test "fails on a server owned interface", %{device: device} do
      interface = "org.astarteplatform.test.ServerDatastream"
      path = "/stringValue"
      value = "123"

      :ok = wait_for_connection()

      assert Device.send_datastream(device, interface, path, value) ==
               {:error, :server_owned_interface}
    end

    test "fails with invalid type", %{device: device} do
      interface = "org.astarteplatform.test.DeviceDatastream"
      path = "/realValue"
      value = "42"

      :ok = wait_for_connection()

      assert Device.send_datastream(device, interface, path, value) ==
               {:error, :unexpected_value_type}
    end

    test "fails with unknown path", %{device: device} do
      interface = "org.astarteplatform.test.DeviceDatastream"
      path = "/invalidPath"
      value = 42.0

      :ok = wait_for_connection()

      assert Device.send_datastream(device, interface, path, value) ==
               {:error, :cannot_resolve_path}
    end

    test "succeeds on a datastream interface", %{device: device} do
      interface = "org.astarteplatform.test.DeviceDatastream"
      path = "/realValue"
      value = 42.0

      full_path = "#{@realm}/#{@device_id}/#{interface}#{path}"

      ConnectionMock
      |> expect(:publish_sync, fn _client_id, ^full_path, bson_value, [] ->
        assert %{"v" => value} = Cyanide.decode!(bson_value)
        :ok
      end)

      :ok = wait_for_connection()

      assert Device.send_datastream(device, interface, path, value) == :ok
    end
  end

  describe "set_property" do
    setup [:set_mox_from_context, :verify_on_exit!, :init_device]

    test "fails on a datastream interface", %{device: device} do
      interface = "org.astarteplatform.test.DeviceDatastream"
      path = "/realValue"
      value = 42.0

      :ok = wait_for_connection()

      assert Device.set_property(device, interface, path, value) ==
               {:error, :datastream_interface}
    end

    test "succeeds on a property interface", %{device: device} do
      interface = "org.astarteplatform.test.DeviceProperties"
      path = "/intValue"
      value = 42

      full_path = "#{@realm}/#{@device_id}/#{interface}#{path}"

      ConnectionMock
      |> expect(:publish_sync, fn _client_id, ^full_path, bson_value, [qos: 2] ->
        assert %{"v" => value} = Cyanide.decode!(bson_value)
        :ok
      end)

      :ok = wait_for_connection()

      assert Device.set_property(device, interface, path, value) == :ok
    end
  end

  describe "unset_property" do
    setup [:set_mox_from_context, :verify_on_exit!, :init_device]

    test "fails on a datastream interface", %{device: device} do
      interface = "org.astarteplatform.test.DeviceDatastream"
      path = "/realValue"
      value = 42.0

      :ok = wait_for_connection()

      assert Device.unset_property(device, interface, path) == {:error, :datastream_interface}
    end

    test "fails on a property interface without allow_unset", %{device: device} do
      interface = "org.astarteplatform.test.DeviceProperties"
      path = "/intValue"
      value = 42

      :ok = wait_for_connection()

      assert Device.unset_property(device, interface, path) == {:error, :unset_not_allowed}
    end

    test "succeeds on a property interface", %{device: device} do
      interface = "org.astarteplatform.test.DeviceProperties"
      path = "/stringValue"
      value = 42

      full_path = "#{@realm}/#{@device_id}/#{interface}#{path}"

      ConnectionMock
      |> expect(:publish_sync, fn _client_id, ^full_path, payload, [qos: 2] ->
        assert payload == <<>>
        :ok
      end)

      :ok = wait_for_connection()

      assert Device.unset_property(device, interface, path) == :ok
    end
  end

  defp init_device(_) do
    test_process = self()
    introspection_topic = @client_id
    empty_cache_topic = "#{@client_id}/control/emptyCache"

    PairingMock
    |> expect(:get_mqtt_v1_credentials, &get_valid_mqtt_v1_credentials/3)
    |> expect(:info, &get_info/2)

    ConnectionMock
    |> expect(:start_link, fn _opts ->
      # Make the device think it's connected
      device_process = self()
      :gen_statem.cast(device_process, {:connection_status, :up})

      {:ok, :not_a_pid}
    end)
    |> expect(:publish_sync, fn @client_id, ^introspection_topic, _payload, opts ->
      assert Keyword.get(opts, :qos) == 2
      :ok
    end)
    |> expect(:publish_sync, fn @client_id, ^empty_cache_topic, "1", opts ->
      assert Keyword.get(opts, :qos) == 2

      # Unblock the test waiting for connection
      send(test_process, :connected)

      :ok
    end)

    opts = [
      pairing_url: @pairing_url,
      realm: @realm,
      device_id: @device_id,
      credentials_secret: @credentials_secret,
      interface_provider: @interfaces_dir
    ]

    {:ok, pid} = Device.start_link(opts)

    %{device: pid}
  end

  defp get_valid_mqtt_v1_credentials(_client, _device_id, _csr) do
    body =
      %{}
      |> put_in(Enum.map(["data", "client_crt"], &Access.key(&1, %{})), @certificate)

    {:ok, %{status: 201, body: body}}
  end

  defp get_info(_client, _device_id) do
    body =
      %{}
      |> put_in(
        Enum.map(["data", "protocols", "astarte_mqtt_v1", "broker_url"], &Access.key(&1, %{})),
        "mqtts://broker.example.com"
      )

    {:ok, %{status: 200, body: body}}
  end

  defp wait_for_connection do
    receive do
      :connected ->
        :ok
    after
      5_000 ->
        {:error, :timeout}
    end
  end
end
