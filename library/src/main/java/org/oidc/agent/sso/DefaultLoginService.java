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
// TODO:discuss on package name
package org.oidc.agent.sso;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.browser.customtabs.CustomTabsIntent;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.TokenResponse;
import org.oidc.agent.config.Configuration;
import org.oidc.agent.exception.ClientException;
import org.oidc.agent.config.FileBasedConfiguration;
import org.oidc.agent.util.Constants;
import org.oidc.agent.util.Util;

import java.io.UnsupportedEncodingException;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

//ToDO: Model hold userinfo response,userinfo: hold login service
//

/**
 * Handles the login process by making use of AppAuth library.
 */
public class DefaultLoginService implements LoginService {

    private final AtomicReference<CustomTabsIntent> customTabIntent = new AtomicReference<>();
    private Configuration mConfiguration;
    private WeakReference<Context> mContext;
    private OAuth2TokenResponse mOAuth2TokenResponse;
    private AuthorizationService mAuthorizationService;
    private static final String LOG_TAG = "LoginService";
    private OIDCDiscoveryResponse mDiscovery;
    private StateManager mStateManager;
    private static DefaultLoginService sDefaultLoginService;

    private DefaultLoginService(Context context) throws ClientException {

        mContext = new WeakReference<>(context);
        mConfiguration = FileBasedConfiguration.getInstance(context);
        mStateManager = StateManager.getInstance(context.getApplicationContext());

    }

    private DefaultLoginService(Context context, Configuration configuration)
            throws ClientException {

        if (mConfiguration == null) {
            new DefaultLoginService(context);
        } else {
            mConfiguration = configuration;
            mContext = new WeakReference<>(context);
            mStateManager = StateManager.getInstance(context.getApplicationContext());
        }
    }

    /**
     * Returns the login service instance.
     *
     * @param context Context
     * @return LoginService
     */
    public static DefaultLoginService getInstance(@NonNull Context context) throws ClientException {

        if (sDefaultLoginService == null) {
            sDefaultLoginService = new DefaultLoginService(context);
        } else if (sDefaultLoginService.mContext.get() == null) {
            sDefaultLoginService.mContext = new WeakReference<>(context);
        }
        return sDefaultLoginService;
    }

    /**
     * Returns LoginService object.
     *
     * @param context       Context
     * @param configuration Configuration
     * @return LoginService
     * @throws ClientException
     */
    public static DefaultLoginService getInstance(@NonNull Context context,
            Configuration configuration) throws ClientException {

        if (sDefaultLoginService == null) {
            sDefaultLoginService = new DefaultLoginService(context, configuration);
        } else if (sDefaultLoginService.mContext.get() == null) {
            sDefaultLoginService.mContext = new WeakReference<>(context);
        }
        return sDefaultLoginService;

    }

    /**
     * Handles the authorization flow by getting the endpoints from discovery service.
     * TODO: catch the errors and pass it to failure intent.
     *
     * @param successIntent successIntent.
     * @param failureIntent failureIntent.
     */
    public void authorize(PendingIntent successIntent, PendingIntent failureIntent) {

        mOAuth2TokenResponse = new OAuth2TokenResponse();
        new OIDCDiscoveryRequest(mConfiguration.getDiscoveryUri().toString(),
                (exception, oidcDiscoveryResponse) -> {
                    if (exception != null) {
                        Log.e(LOG_TAG, "Error while calling discovery endpoint", exception);
                    } else {
                        mDiscovery = oidcDiscoveryResponse;
                        Log.i(LOG_TAG, oidcDiscoveryResponse.getAuthorizationEndpoint().toString());
                        authorizeRequest(TokenManagementActivity
                                .createStartIntent(mContext.get(), successIntent, failureIntent,
                                        mOAuth2TokenResponse), failureIntent);
                    }

                }).execute();
    }

    /**
     * Call authorization endpoint and authorize the request.
     *
     * @param completionIntent CompletionIntent.
     * @param cancelIntent     CancelIntent.
     */
    private void authorizeRequest(PendingIntent completionIntent, PendingIntent cancelIntent) {

        if (mDiscovery != null) {
            AuthorizationServiceConfiguration serviceConfiguration = new AuthorizationServiceConfiguration(
                    mDiscovery.getAuthorizationEndpoint(), mDiscovery.getTokenEndpoint());

            AuthorizationRequest.Builder builder = new AuthorizationRequest.Builder(
                    serviceConfiguration, mConfiguration.getClientId(), ResponseTypeValues.CODE,
                    mConfiguration.getRedirectUri());
            builder.setScopes(mConfiguration.getScope());
            AuthorizationRequest request = builder.build();
            mAuthorizationService = new AuthorizationService(mContext.get());
            CustomTabsIntent.Builder intentBuilder = mAuthorizationService
                    .createCustomTabsIntentBuilder(request.toUri());
            customTabIntent.set(intentBuilder.build());
            mAuthorizationService
                    .performAuthorizationRequest(request, completionIntent, cancelIntent,
                            customTabIntent.get());
            Log.d(LOG_TAG, "Handling authorization request for service provider :" + mConfiguration
                    .getClientId());

        } else {
            Log.d(LOG_TAG, "OIDC discovery response is null");
        }
    }

    /**
     * Handles logout request from the client application.
     */
    public void logout() {

        Map<String, String> paramMap = new HashMap<>();
        if (mOAuth2TokenResponse == null) {
            mOAuth2TokenResponse = getTokenResponse();
        }
        paramMap.put(Constants.ID_TOKEN_HINT, mOAuth2TokenResponse.getIdToken());
        paramMap.put(Constants.POST_LOGOUT_REDIRECT_URI,
                mConfiguration.getRedirectUri().toString());
        try {
            if (mDiscovery != null) {
                String url = Util.buildURLWithQueryParams(mDiscovery.getLogoutEndpoint().toString(),
                        paramMap);
                Log.d(LOG_TAG, "Handling logout request for service provider :" + mConfiguration
                        .getClientId());
                CustomTabsIntent.Builder builder = new CustomTabsIntent.Builder();
                CustomTabsIntent customTabsIntent = builder.build();
                customTabsIntent.intent.setFlags(
                        Intent.FLAG_ACTIVITY_NO_HISTORY | Intent.FLAG_ACTIVITY_NEW_TASK
                                | Intent.FLAG_ACTIVITY_SINGLE_TOP);
                customTabsIntent.launchUrl(mContext.get(), Uri.parse(url));
            }
        } catch (UnsupportedEncodingException e) {
            Log.e(LOG_TAG, "Error while creating logout request", e);
        }
        clearAuthState();
    }

    private void clearAuthState() {

        AuthState currentState = mStateManager.getCurrentAuthState();
        if (currentState.getAuthorizationServiceConfiguration() != null) {
            AuthState clearedState = new AuthState();
            mStateManager.replaceAuthState(clearedState);
        }
    }

    /**
     * Return token response.
     *
     * @return OAuth2TokenResponse
     */
    public OAuth2TokenResponse getTokenResponse() {

        if (mStateManager.getCurrentAuthState().isAuthorized()) {
            if (mOAuth2TokenResponse == null
                    && mStateManager.getCurrentAuthState().getLastTokenResponse() != null) {
                TokenResponse tokenResponse = mStateManager.getCurrentAuthState()
                        .getLastTokenResponse();

                OAuth2TokenResponse response = new OAuth2TokenResponse();
                response.setIdToken(tokenResponse.idToken);
                response.setAccessToken(tokenResponse.accessToken);
                response.setRefreshToken(tokenResponse.refreshToken);
                response.setTokenType(tokenResponse.tokenType);
                mOAuth2TokenResponse = response;

            }
            return mOAuth2TokenResponse;
        }
        return null;
    }

    /**
     * Return userinfo response.
     *
     * @param callback UserInfoResponseCallback.
     */
    public void getUserInfo(UserInfoRequestHandler.UserInfoResponseCallback callback) {

        if (mStateManager.getCurrentAuthState().isAuthorized()) {
            new UserInfoRequestHandler(mContext.get(), mDiscovery, callback).execute();
        } else {
            Log.e(LOG_TAG, "User does not have a authenticated session");
        }
    }

    /**
     * Dispose the authorization service.
     */
    public void dispose() {

        if (mAuthorizationService != null) {
            mAuthorizationService.dispose();
        }
    }

    /**
     * Returns whether the user is logged in or not.
     *
     * @return true if the user is logged in, else returns false.
     */
    public boolean isUserLoggedIn() {

        return mStateManager.getCurrentAuthState().isAuthorized()
                && mStateManager.getCurrentAuthState().getAuthorizationServiceConfiguration()
                != null;
    }
}
