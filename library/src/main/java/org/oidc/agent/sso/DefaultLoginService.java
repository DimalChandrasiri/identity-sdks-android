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

import androidx.browser.customtabs.CustomTabsIntent;

import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.ResponseTypeValues;
import org.oidc.agent.config.Configuration;
import org.oidc.agent.context.AuthenticationContext;
import org.oidc.agent.exception.ClientException;
import org.oidc.agent.config.FileBasedConfiguration;
import org.oidc.agent.handler.OIDCDiscoveryRequestHandler;
import org.oidc.agent.handler.TokenManagementActivity;
import org.oidc.agent.handler.UserInfoRequestHandler;
import org.oidc.agent.model.OAuth2TokenResponse;
import org.oidc.agent.model.OIDCDiscoveryResponse;
import org.oidc.agent.util.Constants;
import org.oidc.agent.util.Util;

import java.io.UnsupportedEncodingException;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Provides authentication and logout support using Identity server.
 */
public class DefaultLoginService implements LoginService {

    private final AtomicReference<CustomTabsIntent> customTabIntent = new AtomicReference<>();
    private Configuration mConfiguration;
    private WeakReference<Context> mContext;
    private OAuth2TokenResponse mOAuth2TokenResponse;
    private AuthorizationService mAuthorizationService;
    private static final String LOG_TAG = "LoginService";
    private OIDCDiscoveryResponse mDiscovery;

    private DefaultLoginService(Context context) throws ClientException {

        mContext = new WeakReference<>(context);
        mConfiguration = FileBasedConfiguration.getInstance(context);
    }

    private DefaultLoginService(Context context, Configuration configuration)
            throws ClientException {

            mConfiguration = configuration;
            mContext = new WeakReference<>(context);
    }


    /**
     * Handles the authorization flow by getting the endpoints from discovery service.
     * TODO: catch the errors and pass it to failure intent.
     *  @param successIntent successIntent.
     * @param failureIntent failureIntent.
     */
    public void authorize(PendingIntent successIntent, PendingIntent failureIntent) {

        // Creating a authentication context object to store context.
        AuthenticationContext authenticationContext = new AuthenticationContext();
        mOAuth2TokenResponse = new OAuth2TokenResponse();
        new OIDCDiscoveryRequestHandler(mConfiguration.getDiscoveryUri().toString(),
                (exception, oidcDiscoveryResponse) -> {
                    if (exception != null) {
                        Log.e(LOG_TAG, "Error while calling discovery endpoint", exception);
                    } else {
                        authenticationContext.setOIDCDiscoveryResponse(oidcDiscoveryResponse);
                        Log.i(LOG_TAG, oidcDiscoveryResponse.getAuthorizationEndpoint().toString());
                        authorizeRequest(TokenManagementActivity
                                .createStartIntent(mContext.get(), successIntent, failureIntent,
                                        mOAuth2TokenResponse, authenticationContext),
                                failureIntent, authenticationContext);
                    }

                }).execute();
    }

    /**
     * Call authorization endpoint and authorize the request.
     *
     * @param completionIntent CompletionIntent.
     * @param cancelIntent     CancelIntent.
     */
    private void authorizeRequest(PendingIntent completionIntent, PendingIntent cancelIntent,
            AuthenticationContext authenticationContext) {

        if ( authenticationContext.getOIDCDiscoveryResponse() != null) {
            mDiscovery = authenticationContext.getOIDCDiscoveryResponse();
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
    public void logout(Context context, AuthenticationContext authenticationContext) {

        OAuth2TokenResponse oAuth2TokenResponse = null;
        Map<String, String> paramMap = new HashMap<>();
        if (authenticationContext.getOAuth2TokenResponse() != null) {
            oAuth2TokenResponse = authenticationContext.getOAuth2TokenResponse();
            paramMap.put(Constants.ID_TOKEN_HINT, oAuth2TokenResponse.getIdToken());
        }

        paramMap.put(Constants.POST_LOGOUT_REDIRECT_URI,
                mConfiguration.getRedirectUri().toString());
        try {
            if (authenticationContext.getOIDCDiscoveryResponse() != null) {
                String url = Util.buildURLWithQueryParams(authenticationContext.getOIDCDiscoveryResponse()
                                .getLogoutEndpoint().toString(),
                        paramMap);
                Log.d(LOG_TAG, "Handling logout request for service provider :" + mConfiguration
                        .getClientId());
                CustomTabsIntent.Builder builder = new CustomTabsIntent.Builder();
                CustomTabsIntent customTabsIntent = builder.build();
                customTabsIntent.intent.setFlags(
                        Intent.FLAG_ACTIVITY_NO_HISTORY | Intent.FLAG_ACTIVITY_NEW_TASK
                                | Intent.FLAG_ACTIVITY_SINGLE_TOP);
                customTabsIntent.launchUrl(context.getApplicationContext(), Uri.parse(url));
            }
        } catch (UnsupportedEncodingException e) {
            Log.e(LOG_TAG, "Error while creating logout request", e);
        }
        dispose();

    }

    /**
     * Return userinfo response.
     *
     * @param callback UserInfoResponseCallback.
     */
    public void getUserInfo(AuthenticationContext context,
            UserInfoRequestHandler.UserInfoResponseCallback callback) {

        if (context.getOAuth2TokenResponse() != null) {
            new UserInfoRequestHandler(context, callback).execute();
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

}
