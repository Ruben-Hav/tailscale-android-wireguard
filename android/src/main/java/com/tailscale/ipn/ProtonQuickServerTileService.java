// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn;

import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;

import com.tailscale.ipn.ui.viewModel.ProtonBridge;

import libtailscale.Libtailscale;

/**
 * Quick Settings tile ("Exit node") that toggles ProtonVPN as the exit on/off.
 * Tapping it on connects Proton to a fresh server (the armed auto-connect country
 * if set, else fastest overall, never the previous server), starting the Tailscale
 * tunnel first if needed; tapping it off disconnects Proton while leaving Tailscale
 * up. The subtitle shows the connected server + load (e.g. "NL#42 · 35%"); the tile
 * is active only while Proton is connected.
 */
public class ProtonQuickServerTileService extends TileService {
    // lock protects currentTile.
    private static final Object lock = new Object();
    private static Tile currentTile;

    /** Refreshes the tile's state; safe to call from any thread / when unbound. */
    public static void updateTile() {
        Tile t;
        synchronized (lock) {
            t = currentTile;
        }
        if (t == null) {
            return;
        }
        boolean active = ProtonBridge.INSTANCE.tileActive();
        UninitializedApp app = UninitializedApp.get();
        t.setLabel(app.getString(R.string.proton_tile_name));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            String subtitle;
            if (active) {
                // Show the connected server + load (e.g. "NL#42 · 35%"); fall back to the
                // generic hint if the server isn't known yet.
                String label = ProtonBridge.INSTANCE.tileServerLabel();
                subtitle = label.isEmpty() ? app.getString(R.string.proton_tile_active) : label;
            } else {
                subtitle = app.getString(R.string.proton_tile_inactive);
            }
            t.setSubtitle(subtitle);
        }
        t.setState(active ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
        t.updateTile();
    }

    @Override
    public void onStartListening() {
        synchronized (lock) {
            currentTile = getQsTile();
        }
        updateTile();
    }

    @Override
    public void onStopListening() {
        synchronized (lock) {
            currentTile = null;
        }
    }

    @Override
    public void onClick() {
        unlockAndRun(this::handleClick);
    }

    private void handleClick() {
        if (ProtonBridge.INSTANCE.tileActive()) {
            // Proton is the exit node — turn it off (Tailscale stays up).
            ProtonBridge.INSTANCE.exitNodeOff();
            return;
        }
        if (!Libtailscale.protonIsLoggedIn()) {
            // Not signed in to Proton; open the app to log in first.
            launchMainActivity();
            return;
        }
        if (Libtailscale.protonVPNTunnelUp()) {
            // Tunnel already up — connect Proton now.
            ProtonBridge.INSTANCE.connectFreshFromTile();
        } else {
            // Need the Tailscale tunnel first; arm Proton to connect once it's up.
            UninitializedApp app = UninitializedApp.get();
            if (!app.isAbleToStartVPN()) {
                launchMainActivity();
                return;
            }
            App.get();
            boolean vpnPrepared = App.get().getAppScopedViewModel().getVpnPrepared().getValue();
            if (vpnPrepared) {
                Libtailscale.protonRequestFreshConnect();
                app.startVPN();
            } else {
                launchMainActivity();
            }
        }
    }

    @SuppressWarnings("deprecation")
    private void launchMainActivity() {
        Intent i = getPackageManager().getLaunchIntentForPackage(getPackageName());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, i,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE));
        } else {
            startActivityAndCollapse(i);
        }
    }
}
