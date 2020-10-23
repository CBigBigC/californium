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
package org.eclipse.californium.extplugtests;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.scandium.DtlsDynClusterConnector.ClusterNodesDiscover;
import org.eclipse.californium.scandium.config.DtlsClusterConfig;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

public class K8sManagementClient implements ClusterNodesDiscover {

	private static final Logger LOGGER = LoggerFactory.getLogger(K8sManagementClient.class);

	private static final int CONNECT_TIMEOUT_MILLIS = 2000;
	private static final int REQUEST_TIMEOUT_MILLIS = 2000;

	private final int externalPort;

	private final int nodeId;
	private final String hostName;

	private final String hostUrl;
	private final String token;
	private final String namespace;
	private final String selector;
	private final SSLContext sslContext;
	private final DtlsClusterConfig config;

	private final List<String> discoverScope = new ArrayList<>();

	public K8sManagementClient(int externalPort) throws GeneralSecurityException, IOException {
		this.hostName = InetAddress.getLocalHost().getHostName();
		this.externalPort = externalPort;
		Integer node = null;
		String id = StringUtil.getConfiguration("KUBECTL_NODE_ID");
		if (id != null && !id.isEmpty()) {
			try {
				node = Integer.valueOf(id);
			} catch (NumberFormatException ex) {
				LOGGER.warn("KUBECTL_NODE_ID: {}", id, ex);
			}
		}
		if (node == null) {
			int pos = hostName.lastIndexOf("-");
			if (pos >= 0) {
				id = hostName.substring(pos + 1);
				try {
					node = Integer.valueOf(id);
				} catch (NumberFormatException ex) {
					LOGGER.warn("HOSTNAME: {}", hostName, ex);
				}
			}
		}
		if (node != null) {
			nodeId = node;
		} else {
			throw new IllegalArgumentException("node-id not available!");
		}
		DtlsClusterConfig.Builder builder = DtlsClusterConfig.builder();
		String identity = StringUtil.getConfiguration("DTLS_CID_MGMT_IDENTITY");
		String secret = StringUtil.getConfiguration("DTLS_CID_MGMT_SECRET_BASE64");
		if (identity != null && secret != null) {
			byte[] secretBytes = StringUtil.base64ToByteArray(secret);
			SecretKey key = SecretUtil.create(secretBytes, "PSK");
			Arrays.fill(secretBytes, (byte) 0);
			builder.setSecure(identity, key);
			SecretUtil.destroy(key);
		}
		this.config = builder.build();
		this.hostUrl = StringUtil.getConfiguration("KUBECTL_HOST");
		this.token = StringUtil.getConfiguration("KUBECTL_TOKEN");
		this.namespace = StringUtil.getConfiguration("KUBECTL_NAMESPACE");
		this.selector = StringUtil.getConfiguration("KUBECTL_SELECTOR");
		String trustStore = StringUtil.getConfiguration("KUBECTL_TRUSTSTORE");
		Certificate[] trusts = null;
		if (trustStore != null && !trustStore.isEmpty()) {
			trusts = SslContextUtil.loadTrustedCertificates(trustStore);
		}
		LOGGER.info("Node-ID: {} - {}", nodeId, externalPort);
		LOGGER.info("{} / {} / {}", hostUrl, namespace, selector);
		int len = token.length();
		int end = len > 20 ? 10 : len / 2;
		LOGGER.info("{}... ({} bytes)", token.substring(0, end), len);
		KeyManager[] keyManager = SslContextUtil.createAnonymousKeyManager();
		TrustManager[] trustManager;
		if (trusts == null || trusts.length == 0) {
			trustManager = SslContextUtil.createTrustAllManager();
		} else {
			trustManager = SslContextUtil.createTrustManager("trusts", trusts);
		}
		sslContext = SSLContext.getInstance("TLSv1.3");
		sslContext.init(keyManager, trustManager, null);
	}

	public int getNodeID() {
		return nodeId;
	}

	public void getPods() throws ClientProtocolException, IOException, GeneralSecurityException {
		CloseableHttpClient client = HttpClientBuilder.create().setSSLContext(sslContext).build();
		StringBuilder url = new StringBuilder(hostUrl);
		url.append("/api/v1/namespaces/");
		if (namespace != null) {
			url.append(namespace);
		} else {
			url.append("default");
		}
		url.append("/pods");
		if (selector != null) {
			url.append("?labelSelector=").append(selector);
		}
		HttpGet request = new HttpGet(url.toString());
		request.addHeader("Authorization", "Bearer " + token);
		RequestConfig config = RequestConfig.custom().setConnectTimeout(CONNECT_TIMEOUT_MILLIS)
				.setConnectionRequestTimeout(REQUEST_TIMEOUT_MILLIS).build();
		request.setConfig(config);
		HttpResponse response = client.execute(request);

		// Get the response
		Reader reader = new InputStreamReader(response.getEntity().getContent());
		JsonParser parser = new JsonParser();
		JsonElement element = parser.parse(reader);

		Set<Pod> pods = new HashSet<>();

		if (LOGGER.isDebugEnabled()) {
			GsonBuilder builder = new GsonBuilder();
			builder.setPrettyPrinting();
			Gson gson = builder.create();
			LOGGER.debug("{}", gson.toJson(element));
		}
		JsonElement childElement = getChild(element, "items");
		if (childElement != null && childElement.isJsonArray()) {
			JsonArray jsonArray = childElement.getAsJsonArray();
			for (JsonElement item : jsonArray) {
				String name = null;
				String phase = null;
				String group = null;
				String address = null;
				Set<String> addresses = new HashSet<>();
				childElement = getChild(item, "metadata/name");
				if (childElement != null) {
					name = childElement.getAsString();
				}
				childElement = getChild(item, "metadata/labels/controller-revision-hash");
				if (childElement == null) {
					childElement = getChild(item, "metadata/labels/pod-template-hash");
					if (childElement == null) {
						childElement = getChild(item, "metadata/labels/deployment");
					}
				}
				if (childElement != null) {
					group = childElement.getAsString();
				}
				childElement = getChild(item, "status/phase");
				if (childElement != null) {
					phase = childElement.getAsString();
				}
				childElement = getChild(item, "status/podIP");
				if (childElement != null) {
					address = childElement.getAsString();
					addresses.add(address);
				}
				childElement = getChild(item, "status/podIPs");
				if (childElement != null && childElement.isJsonArray()) {
					JsonArray ipArray = childElement.getAsJsonArray();
					for (JsonElement ip : ipArray) {
						if (ip.isJsonObject()) {
							childElement = getChild(ip, "ip");
							if (childElement != null) {
								String multiAddress = childElement.getAsString();
								if (address == null) {
									address = multiAddress;
								}
								addresses.add(multiAddress);
							}
						}
					}
				}
				pods.add(new Pod(name, group, phase, address, addresses));
			}
		}

		for (Pod pod : pods) {
			if (pod.addresses.size() > 1) {
				LOGGER.info("{} ({}) => {}: {}", pod.name, pod.group, pod.phase, pod.addresses);
			} else {
				LOGGER.info("{} ({}) => {}: {}", pod.name, pod.group, pod.phase, pod.address);
			}
		}
		LOGGER.info("host: {}", hostName);
		synchronized (discoverScope) {
			discoverScope.clear();
			for (Pod pod : pods) {
				if (pod.address != null && !hostName.equals(pod.name)) {
					discoverScope.add(pod.address);
				}
			}
		}
	}

	private JsonElement getChild(JsonElement element, String path) {
		String[] pathItems = path.split("/");
		return getChild(element, pathItems, 0);
	}

	private JsonElement getChild(JsonElement element, String[] path, int pathIndex) {
		JsonElement current = null;
		String name = path[pathIndex];
		if (element.isJsonArray()) {
			JsonArray jsonArray = element.getAsJsonArray();
			int index = Integer.parseInt(name);
			current = jsonArray.get(index);
		} else if (element.isJsonObject()) {
			JsonObject jsonObject = element.getAsJsonObject();
			current = jsonObject.get(name);
		}
		if (current != null && pathIndex + 1 < path.length) {
			return getChild(current, path, pathIndex + 1);
		}
		return current;
	}

	private static class Pod {

		private final String name;
		private final String group;
		private final String phase;
		private final String address;
		private final Set<String> addresses;

		private Pod(String name, String group, String phase, String address, Set<String> addresses) {
			this.name = name;
			this.group = group;
			this.phase = phase;
			this.address = address;
			this.addresses = addresses;
		}
	}

	@Override
	public List<InetSocketAddress> getClusterNodesDiscoverScope() {
		List<InetSocketAddress> scope = new ArrayList<>();
		try {
			getPods();
			synchronized (discoverScope) {
				for (String address : discoverScope) {
					scope.add(new InetSocketAddress(address, externalPort));
				}
			}
		} catch (ClientProtocolException e) {
			LOGGER.error("error: ", e);
		} catch (IOException e) {
			LOGGER.error("error: ", e);
		} catch (GeneralSecurityException e) {
			LOGGER.error("error: ", e);
		}
		return scope;
	}

	@Override
	public DtlsClusterConfig getConfiguration() {
		return config;
	}
}
