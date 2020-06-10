/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.oidc.agent.sso;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import androidx.annotation.Nullable;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.TokenResponse;
import net.openid.appauth.internal.Logger;
import org.oidc.agent.context.AuthenticationContext;
import org.oidc.agent.context.StateManager;
import org.oidc.agent.model.OAuth2TokenResponse;

public class TokenManagementActivity extends Activity {

    static final String KEY_COMPLETE_INTENT = "completeIntent";
    static final String KEY_CANCEL_INTENT = "cancelIntent";
    private static final String LOG_TAG = "TokenManagementActivity";
    private AuthorizationService mAuthorizationService;
    PendingIntent mCompleteIntent;
    PendingIntent mCancelIntent;
    private static OAuth2TokenResponse sResponse;
    private StateManager mStateManager;
    static AuthenticationContext mAuthenticationContext;

    static PendingIntent createStartIntent(Context context, PendingIntent completeIntent,
            PendingIntent cancelIntent, OAuth2TokenResponse response, AuthenticationContext authenticationContext) {

        Intent tokenExchangeIntent = new Intent(context, TokenManagementActivity.class);
        tokenExchangeIntent.putExtra(KEY_COMPLETE_INTENT, completeIntent);
        tokenExchangeIntent.putExtra(KEY_CANCEL_INTENT, cancelIntent);
        sResponse = response;
        mAuthenticationContext = authenticationContext;

        return PendingIntent
                .getActivity(context, 0, tokenExchangeIntent, PendingIntent.FLAG_UPDATE_CURRENT);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        mAuthorizationService = new AuthorizationService(this);
        mStateManager = StateManager.getInstance(this);
        if (savedInstanceState == null) {
            extractState(getIntent().getExtras());
        } else {
            extractState(savedInstanceState);
        }

    }

    @Override
    protected void onStart() {

        super.onStart();
        AuthorizationException ex = AuthorizationException.fromIntent(getIntent());
        if (ex != null) {
            Log.w(LOG_TAG, "Authorization flow failed: " + ex);
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    sendPendingIntent(mCancelIntent);
                }
            });
        } else {
            AuthorizationResponse response = AuthorizationResponse.fromIntent(getIntent());

            if (response != null) {
                handleAuthorizationResponse(response);
                mStateManager.updateAfterAuthorization(response, ex);
            }
        }
    }

    @Override
    protected void onDestroy() {

        super.onDestroy();
        finish();
    }

    private void handleAuthorizationResponse(AuthorizationResponse response) {

        mAuthorizationService.performTokenRequest(response.createTokenExchangeRequest(),
                this::handleTokenResponse);

    }

    private void handleTokenResponse(@Nullable TokenResponse tokenResponse,
            @Nullable AuthorizationException exception) {

        if (exception != null) {
            Log.e(LOG_TAG, "Token Exchange failed", exception);
        } else {
            if (tokenResponse != null) {
                Log.d(LOG_TAG, String.format("Token Response [ Access Token: %s, ID Token: %s ]",
                        tokenResponse.accessToken, tokenResponse.idToken));
                if (mCompleteIntent != null) {
                    Logger.debug("Authorization complete - invoking completion intent");
                    sResponse.setAccessToken(tokenResponse.accessToken);
                    sResponse.setIdToken(tokenResponse.idToken);
                    sResponse.setAccessTokenExpirationTime(tokenResponse.accessTokenExpirationTime);
                    sResponse.setRefreshToken(tokenResponse.refreshToken);
                    sResponse.setTokenType(tokenResponse.tokenType);
                    mAuthenticationContext.setOAuth2TokenResponse(sResponse);

                    Intent intent = new Intent(this, mCompleteIntent.getIntentSender().getClass());
                    mStateManager.updateAfterTokenResponse(tokenResponse, exception);
                    intent.putExtra("context", mAuthenticationContext);
                    try {
                        mCompleteIntent.send(this, 0,intent);
                    } catch (PendingIntent.CanceledException e) {
                        e.printStackTrace();
                    }
                    mAuthorizationService.dispose();
                }
            } else {
                sendPendingIntent(mCancelIntent);
            }
        }
        finish();
    }

    private void sendPendingIntent(PendingIntent pendingIntent) {

        try {
            pendingIntent.send();
        } catch (PendingIntent.CanceledException e) {
            Log.e(LOG_TAG, "Unable to send intent", e);
        }
        finish();
    }

    void extractState(Bundle state) {

        if (state == null) {
            Log.d(LOG_TAG, "Cannot handle response");
            finish();
            return;
        }
        mCompleteIntent = state.getParcelable(KEY_COMPLETE_INTENT);
        mCancelIntent = state.getParcelable(KEY_CANCEL_INTENT);
    }

}
