// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

// No polling or fixed sleep: an already validated network completes immediately.
// Always release the callback, including timeout and interrupted worker threads.
internal fun awaitProtonVpnReadiness(
    timeoutMillis: Long,
    subscribe: (onReady: () -> Unit) -> (() -> Unit),
): Boolean {
  val ready = CountDownLatch(1)
  val unsubscribe = subscribe { ready.countDown() }
  return try {
    ready.await(timeoutMillis, TimeUnit.MILLISECONDS)
  } finally {
    unsubscribe()
  }
}
