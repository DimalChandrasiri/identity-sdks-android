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

package org.oidc.agent.context;

import android.content.Context;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import androidx.annotation.RequiresApi;
import net.openid.appauth.AuthorizationService;
import org.oidc.agent.config.Configuration;
import org.oidc.agent.model.OAuth2TokenResponse;
import org.oidc.agent.model.OIDCDiscoveryResponse;
import org.oidc.agent.model.UserInfoResponse;
import org.oidc.agent.sso.DefaultLoginService;

import java.io.Serializable;
import java.lang.ref.WeakReference;

public class AuthenticationContext implements Serializable {

    private OAuth2TokenResponse mOAuth2TokenResponse;
    private static final String LOG_TAG = "AuthenticationContext";
    private OIDCDiscoveryResponse mDiscoveryResponse;
    private UserInfoResponse mUserInfoResponse;
    private String name;


    public AuthenticationContext() {
    }

    protected AuthenticationContext(Parcel in) {
        name = in.readString();
    }


    public void setOIDCDiscoveryResponse(OIDCDiscoveryResponse oidcDiscoveryResponse){
        this.mDiscoveryResponse = oidcDiscoveryResponse;
    }

    public void setOAuth2TokenResponse(OAuth2TokenResponse oAuth2TokenResponse){
        this.mOAuth2TokenResponse = oAuth2TokenResponse;
    }

    public void setUserInfoResponse(UserInfoResponse userInfoResponse){
        this.mUserInfoResponse = userInfoResponse;
    }

    public OAuth2TokenResponse getOAuth2TokenResponse(){
        return mOAuth2TokenResponse;
    }

    public OIDCDiscoveryResponse getOIDCDiscoveryResponse(){
        return mDiscoveryResponse;
    }

    public UserInfoResponse getUserInfoResponse(){
        return mUserInfoResponse;
    }

    public void setName(String name){
        this.name = name;
    }

    public String getName(){
        return name;
    }
}
