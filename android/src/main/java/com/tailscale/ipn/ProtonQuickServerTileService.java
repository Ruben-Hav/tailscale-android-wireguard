// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn;

import android.app.PendingIntent;
import android.content.Intent;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import android.widget.Toast;

import com.tailscale.ipn.ui.viewModel.ProtonBridge;

/**
 * Quick Settings tile that shuffles to the fastest OTHER ProtonVPN server in the
 * country you're currently connected to ("Fastest server"). Only meaningful
 * while Proton is connected; otherwise tapping it opens the app so you can
 * connect first.
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
            t.setSubtitle(app.getString(active ? R.string.proton_tile_active : R.string.proton_tile_inactive));
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
        if (!ProtonBridge.INSTANCE.tileActive()) {
            // Not connected — there's nothing to shuffle; open the app instead.
            launchMainActivity();
            return;
        }
        Toast.makeText(this, R.string.proton_tile_switching, Toast.LENGTH_SHORT).show();
        ProtonBridge.INSTANCE.fastestInCountryFromTile();
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
