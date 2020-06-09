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

import android.util.Log;
import android.content.Context;
import android.content.SharedPreferences;

import java.lang.ref.WeakReference;
import java.util.concurrent.atomic.AtomicReference;

import androidx.annotation.AnyThread;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.TokenResponse;

import org.json.JSONException;

import static org.oidc.agent.util.Constants.AUTH_STATE;
import static org.oidc.agent.util.Constants.AUTH_STORE_NAME;
import static org.oidc.agent.util.Constants.USER_STATE;
import static org.oidc.agent.util.Constants.USER_STORE_NAME;

/**
 * A mechanism for handling the AuthState.
 */
public class StateManager {

    private static final AtomicReference<WeakReference<StateManager>> STATE_MANAGER_REF = new AtomicReference<>(
            new WeakReference<StateManager>(null));

    private final SharedPreferences authPrefs;
    private final AtomicReference<AuthState> currentAuthState;
    private final AtomicReference<UserInfoState> currentuserinfoState;
    private final String TAG = StateManager.class.getSimpleName();

    private StateManager(Context context) {

        authPrefs = context.getSharedPreferences(AUTH_STORE_NAME, Context.MODE_PRIVATE);
        currentAuthState = new AtomicReference<>();
        currentuserinfoState = new AtomicReference<>();
    }

    /**
     * Returns an instance of the AuthStateManager class.
     *
     * @param context Application context.
     * @return AuthStateManager instance.
     */
    @AnyThread
    public static StateManager getInstance(@NonNull Context context) {

        StateManager stateManager = STATE_MANAGER_REF.get().get();
        if (stateManager == null) {
            stateManager = new StateManager(context.getApplicationContext());
            STATE_MANAGER_REF.set(new WeakReference<>(stateManager));
        }

        return stateManager;
    }

    /**
     * Returns the current AuthState instance.
     *
     * @return Current AuthState instance.
     */
    @AnyThread
    @NonNull
    public AuthState getCurrentAuthState() {

        AuthState current;
        if (currentAuthState.get() != null) {
            current = currentAuthState.get();
        } else {
            AuthState state = readAuthState();
            if (currentAuthState.compareAndSet(null, state)) {
                current = state;
            } else {
                current = currentAuthState.get();
            }
        }
        return current;
    }

    /**
     * Replaces the current AuthState with a new AuthState.
     *
     * @param state AuthState object that is to replace the existing one.
     */
    @AnyThread
    public void replaceAuthState(@NonNull AuthState state) {

        writeAuthState(state);
        currentAuthState.set(state);
    }

    /**
     * Updates the current AuthState with authorization response and exception.
     *
     * @param response Authorization response.
     * @param ex       Authorization exception.
     */
    @AnyThread
    public void updateAfterAuthorization(@Nullable AuthorizationResponse response,
            @Nullable AuthorizationException ex) {

        AuthState current = getCurrentAuthState();
        current.update(response, ex);
        replaceAuthState(current);
    }

    /**
     * Updates the current AuthState with token response and exception.
     *
     * @param response Token response.
     * @param ex       Authorization exception.
     */
    @AnyThread
    public void updateAfterTokenResponse(@Nullable TokenResponse response,
            @Nullable AuthorizationException ex) {

        AuthState current = getCurrentAuthState();
        current.update(response, ex);
        replaceAuthState(current);
    }

    /**
     * Reads the AuthState.
     *
     * @return AuthState object.
     */
    @AnyThread
    @NonNull
    private AuthState readAuthState() {

        AuthState auth;
        String currentState = authPrefs.getString(AUTH_STATE, null);
        if (currentState == null) {
            auth = new AuthState();
        } else {
            try {
                auth = AuthState.jsonDeserialize(currentState);
            } catch (JSONException ex) {
                Log.e(TAG, "Failed to deserialize stored auth state - discarding: ", ex);
                auth = new UserInfoState();
            }
        }
        return auth;
    }

    /**
     * Writes the AuthState.
     *
     * @param state AuthState object.
     */
    @AnyThread
    private void writeAuthState(@Nullable AuthState state) {

        SharedPreferences.Editor editor = authPrefs.edit();
        if (state == null) {
            editor.remove(AUTH_STATE);
        } else {
            editor.putString(AUTH_STATE, state.jsonSerializeString());
        }
        if (!editor.commit()) {
            Log.e(TAG, "Failed to write state to shared prefs.");
        }
    }

    /**
     * Get current state of userinfo.
     *
     * @return UserInfoState.
     */
    @AnyThread
    public UserInfoState getCurrentUserState() {

        UserInfoState current = null;
        if (currentuserinfoState.get() != null) {
            current = currentuserinfoState.get();
        } else {
            UserInfoState state = readUserState();
            if (currentuserinfoState.compareAndSet(null, state)) {
                current = state;
            } else {
                current = currentuserinfoState.get();
            }
        }
        return current;
    }

    /**
     * Read the userinfo state.
     *
     * @return UserInfo State
     */
    @AnyThread
    private UserInfoState readUserState() {

        UserInfoState userInfoState;
        String currentState = authPrefs.getString(USER_STATE, null);
        if (currentState == null) {
            userInfoState = new UserInfoState();
        } else {
            try {
                userInfoState = UserInfoState.jsonDeserialize(currentState);
            } catch (JSONException ex) {
                Log.e(TAG, "Failed to deserialize stored auth state - discarding: ", ex);
                userInfoState = new UserInfoState();
            }
        }
        return userInfoState;
    }

    /**
     * Update the userinfo state.
     *
     * @param response UserInfoResponse
     * @return UserinfoState
     */
    @AnyThread
    public void updateAfterUserInfoState(UserInfoResponse response) {

        UserInfoState current = getCurrentUserState();
        current.update(response);
        writeUserState(current);
        currentuserinfoState.set(current);
    }

    /**
     * Write the userstate in shared preference.
     *
     * @param state UserInfoState.
     */
    @AnyThread
    private void writeUserState(@Nullable UserInfoState state) {

        SharedPreferences.Editor editor = authPrefs.edit();
        if (state == null) {
            editor.remove(USER_STATE);
        } else {
            editor.putString(USER_STATE, state.jsonSerializeString());
        }
        if (!editor.commit()) {
            Log.e(TAG, "Failed to write state to shared prefs.");
        }
    }
}
