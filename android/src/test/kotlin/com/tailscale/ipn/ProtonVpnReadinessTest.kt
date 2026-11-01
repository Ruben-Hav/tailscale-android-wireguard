// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProtonVpnReadinessTest {
  @Test
  fun validatedNetworkCompletesWithoutDelayAndReleasesCallback() {
    var released = false
    assertTrue(awaitProtonVpnReadiness(0) { ready ->
      val unsubscribe = { released = true }
      ready()
      unsubscribe
    })
    assertTrue(released)
  }

  @Test
  fun timeoutReleasesCallback() {
    var released = false
    assertFalse(awaitProtonVpnReadiness(0) { { released = true } })
    assertTrue(released)
  }

  @Test
  fun interruptedWorkerReleasesCallback() {
    var released = false
    Thread.currentThread().interrupt()
    try {
      awaitProtonVpnReadiness(500) { { released = true } }
      throw AssertionError("interrupted wait returned normally")
    } catch (_: InterruptedException) {
      assertTrue(released)
    } finally {
      Thread.interrupted()
    }
  }
}
