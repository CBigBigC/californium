/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.config;

import javax.crypto.SecretKey;

import org.eclipse.californium.scandium.util.SecretUtil;

/**
 * DTLS cluster configuration.
 * 
 * @since 2.5
 */
public final class DtlsClusterConfig {

	public static final long DEFAULT_TIMER_INTERVAL_MILLIS = 2000;
	public static final long DEFAULT_REFRESH_INTERVAL_MILLIS = 6000;
	public static final long DEFAULT_EXPIRES_MILLIS = 2 * DEFAULT_TIMER_INTERVAL_MILLIS;
	public static final long DEFAULT_DISCOVER_INTERVAL_MILLIS = 30000;

	private String identity;

	private SecretKey secret;

	private Long timerIntervalMillis;

	private Long refreshIntervalMillis;

	private Long expiresMillis;

	private Long discoverIntervalMillis;

	public String getSecureIdentity() {
		return identity;
	}

	public SecretKey getSecretKey() {
		return SecretUtil.create(secret);
	}

	public long getTimerIntervalMillis() {
		return timerIntervalMillis;
	}

	public long getRefreshIntervalMillis() {
		return refreshIntervalMillis;
	}

	public long getExpiresMillis() {
		return expiresMillis;
	}

	public long getDiscoverIntervalMillis() {
		return discoverIntervalMillis;
	}

	/**
	 * @return a copy of this configuration
	 */
	@Override
	protected Object clone() {
		DtlsClusterConfig cloned = new DtlsClusterConfig();
		cloned.identity = identity;
		cloned.secret = SecretUtil.create(secret);
		cloned.timerIntervalMillis = timerIntervalMillis;
		cloned.refreshIntervalMillis = refreshIntervalMillis;
		cloned.expiresMillis = expiresMillis;
		cloned.discoverIntervalMillis = discoverIntervalMillis;
		return cloned;
	}

	public static Builder builder() {
		return new Builder();
	}

	public static Builder builder(DtlsClusterConfig config) {
		return new Builder(config);
	}

	public static final class Builder {

		private DtlsClusterConfig config;

		public Builder() {
			config = new DtlsClusterConfig();
		}

		public Builder(DtlsClusterConfig initialConfiguration) {
			config = (DtlsClusterConfig) initialConfiguration.clone();
		}

		public Builder setSecure(String identity, SecretKey secret) {
			if (identity == null && secret != null) {
				throw new IllegalArgumentException("No identity but secret!");
			}
			if (identity != null && secret == null) {
				throw new IllegalArgumentException("No secret but identity!");
			}
			if (config.secret != null) {
				SecretUtil.destroy(config.secret);
			}
			config.identity = identity;
			config.secret = SecretUtil.create(secret);
			return this;
		}

		public Builder setTimerIntervalMillis(Long millis) {
			config.timerIntervalMillis = millis;
			return this;
		}

		public Builder setRefreshIntervalMillis(Long millis) {
			config.refreshIntervalMillis = millis;
			return this;
		}

		public Builder setExpiresMillis(Long millis) {
			config.expiresMillis = millis;
			return this;
		}

		public Builder setDiscoverIntervalMillis(Long millis) {
			config.discoverIntervalMillis = millis;
			return this;
		}

		/**
		 * Returns a potentially incomplete configuration. Only fields set by
		 * users are affected, there is no default value, no consistency check.
		 * To get a full usable {@link DtlsClusterConfig} use {@link #build()}
		 * instead.
		 * 
		 * @return the incomplete Configuration
		 */
		public DtlsClusterConfig getIncompleteConfig() {
			return config;
		}

		public DtlsClusterConfig build() {
			// set default values
			if (config.timerIntervalMillis == null) {
				config.timerIntervalMillis = DEFAULT_TIMER_INTERVAL_MILLIS;
			}
			if (config.refreshIntervalMillis == null) {
				config.refreshIntervalMillis = DEFAULT_REFRESH_INTERVAL_MILLIS;
			}
			if (config.expiresMillis == null) {
				config.expiresMillis = config.timerIntervalMillis * 2;
			}
			if (config.discoverIntervalMillis == null) {
				config.discoverIntervalMillis = DEFAULT_DISCOVER_INTERVAL_MILLIS;
			}
			return config;
		}

	}
}
