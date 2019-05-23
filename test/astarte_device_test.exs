defmodule Astarte.DeviceTest do
  use ExUnit.Case
  doctest Astarte.Device

  test "greets the world" do
    assert Astarte.Device.hello() == :world
  end
end
