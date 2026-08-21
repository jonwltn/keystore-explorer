/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.kse.gui.actions;

import org.kse.crypto.keystore.KeyStoreUtil;
import org.kse.crypto.keystore.KseKeyStore;
import org.kse.crypto.keystore.MsCapiStoreType;
import org.kse.gui.KseFrame;
import org.kse.gui.error.DError;
import org.kse.utilities.history.KeyStoreHistory;

/**
 * Action to open the MS CAPI KeyStore.
 */
public abstract class OpenMsCapiAction extends OpenAction {

    private static final long serialVersionUID = -9068103518220241052L;

    private MsCapiStoreType type;
    private String tabTitleKey;

    OpenMsCapiAction(KseFrame kseFrame, MsCapiStoreType type, String tabTitleKey) {
        super(kseFrame);
        this.type = type;
        this.tabTitleKey = tabTitleKey;
    }

    /**
     * Do action.
     */
    @Override
    protected void doAction() {

        try {

            KseKeyStore openedKeyStore = KeyStoreUtil.loadMsCapiStore(type);

            // Set provider for signing operations. See note in GenerateKeyPairAction.
            var history = new KeyStoreHistory(openedKeyStore, res.getString(tabTitleKey), null, openedKeyStore.getProvider());

            kseFrame.addKeyStoreHistory(history);

        } catch (Exception ex) {
            DError.displayError(frame, ex);
        }
    }

}
