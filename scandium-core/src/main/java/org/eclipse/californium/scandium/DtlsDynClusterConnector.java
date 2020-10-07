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
package org.eclipse.californium.scandium;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.MessageCallback;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.WipAPI;
import org.eclipse.californium.scandium.config.DtlsClusterConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.SessionCache;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.util.SecretUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DTLS dynamic cluster connector.
 * 
 * Discover and update cluster cid nodes associations dynamically.
 * 
 * @since 2.5
 */
@WipAPI
public class DtlsDynClusterConnector extends DtlsClusterConnector {

	private static final Logger LOGGER = LoggerFactory.getLogger(DtlsDynClusterConnector.class);

	/**
	 * Type of cluster management node-id request.
	 */
	private static final byte MAGIC_ID_PING = (byte) 61;

	/**
	 * Type of cluster management node-id response.
	 */
	private static final byte MAGIC_ID_PONG = (byte) 60;

	/**
	 * Protocol for cluster management.
	 */
	private final String protocol;

	/**
	 * Cluster nodes discover callback.
	 */
	private final ClusterNodesDiscover discoverScope;

	/**
	 * Discover and provide nodes for cluster.
	 */
	private final NodesDiscoverer nodesDiscoverer;

	/**
	 * Logging callback for sending cluster management messages.
	 */
	private final MessageCallback messageLoggingCallback = new MessageCallback() {

		@Override
		public void onSent() {
			LOGGER.trace("cluster-node {} ({}): sent", nodeId, protocol);
		}

		@Override
		public void onError(Throwable error) {
			LOGGER.info("cluster-node {} ({}): error", nodeId, protocol, error);
		}

		@Override
		public void onDtlsRetransmission(int flight) {
			LOGGER.trace("cluster-node {} ({}): retransmission flight {}", nodeId, protocol, flight);
		}

		@Override
		public void onContextEstablished(EndpointContext context) {
			LOGGER.trace("cluster-node {} ({}): context established", nodeId, protocol);
		}

		@Override
		public void onConnecting() {
			LOGGER.trace("cluster-node {} ({}): connecting ...", nodeId, protocol);
		}
	};

	/**
	 * Principal for encrypted cluster management communication. {@code null},
	 * if encryption is not used.
	 */
	private final Principal principal;

	/**
	 * Schedule for cluster management timer.
	 */
	private volatile ScheduledFuture<?> schedule;

	/**
	 * Connector for cluster management.
	 */
	private volatile ClusterManagementConnector clusterManagementConnector;

	/**
	 * Create dtls connector with dynamic cluster support.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterInternalSocketAddress Socket address for cluster internal
	 *            communication
	 * @param nodes cluster nodes discoverer
	 */
	public DtlsDynClusterConnector(DtlsConnectorConfig configuration, InetSocketAddress clusterInternalSocketAddress,
			ClusterNodesDiscover nodes) {
		this(configuration, clusterInternalSocketAddress, nodes, null);
	}

	/**
	 * Create dtls connector with dynamic cluster support.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterInternalSocketAddress Socket address for cluster internal
	 *            communication
	 * @param nodes cluster nodes discoverer
	 * @param sessionCache session cache
	 */
	public DtlsDynClusterConnector(DtlsConnectorConfig configuration, InetSocketAddress clusterInternalSocketAddress,
			ClusterNodesDiscover nodes, SessionCache sessionCache) {
		super(configuration, clusterInternalSocketAddress, sessionCache);
		this.discoverScope = nodes;
		this.nodesDiscoverer = new NodesDiscoverer();
		this.nodesProvider = this.nodesDiscoverer;
		String identity = discoverScope.getConfiguration().getSecureIdentity();
		if (identity == null) {
			this.protocol = "mgmt-udp";
			this.principal = null;
		} else {
			this.protocol = "mgmt-dtls";
			this.principal = new PreSharedKeyIdentity(identity);
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Creates socket and threads for cluster internal communication.
	 */
	@Override
	protected void init(InetSocketAddress bindAddress, DatagramSocket socket, Integer mtu) throws IOException {
		super.init(bindAddress, socket, mtu);
		Integer mgmtReceiveBuffer = add(config.getSocketReceiveBufferSize(), DATAGRAM_OFFSET);
		Integer mgmtSendBuffer = add(config.getSocketSendBufferSize(), DATAGRAM_OFFSET);
		Integer mgmtMtu = add(mtu, DATAGRAM_OFFSET);
		String identity = discoverScope.getConfiguration().getSecureIdentity();
		LOGGER.info("cluster-node {} ({}): recv. buffer {}, send buffer {}, MTU {}", nodeId, protocol,
				mgmtReceiveBuffer, mgmtSendBuffer, mgmtMtu);
		if (identity != null) {
			SecretKey secretkey = discoverScope.getConfiguration().getSecretKey();
			DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder().setAddress(clusterInternalSocketAddress)
					.setReceiverThreadCount(0).setMaxConnections(1024).setSocketReceiveBufferSize(mgmtReceiveBuffer)
					.setSocketSendBufferSize(mgmtSendBuffer)
					.setAdvancedPskStore(new AdvancedSinglePskStore(identity, secretkey));
			if (mgmtMtu != null) {
				builder.setMaxTransmissionUnit(mgmtMtu);
			}
			clusterManagementConnector = new ClusterManagementDtlsConnector(builder.build(), clusterInternalSocket);
			SecretUtil.destroy(secretkey);
		} else {
			ClusterManagementUdpConnector connector = new ClusterManagementUdpConnector(clusterInternalSocketAddress,
					clusterInternalSocket);
			connector.setReceiverThreadCount(0);
			connector.setSenderThreadCount(2);
			if (mgmtReceiveBuffer != null) {
				connector.setReceiveBufferSize(mgmtReceiveBuffer);
			}
			if (mgmtSendBuffer != null) {
				connector.setSendBufferSize(mgmtSendBuffer);
			}
			if (mgmtMtu != null) {
				connector.setReceiverPacketSize(mgmtMtu);
			}
			clusterManagementConnector = connector;
		}
		clusterManagementConnector.setRawDataReceiver(new RawDataChannel() {

			@Override
			public void receiveData(RawData clusterData) {
				processMessageFromClusterManagement(clusterData);
			}
		});
		clusterManagementConnector.start();
		long intervalMillis = discoverScope.getConfiguration().getTimerIntervalMillis();
		schedule = timer.scheduleWithFixedDelay(new Runnable() {

			@Override
			public void run() {
				try {
					nodesDiscoverer.process(clusterManagementConnector);
				} catch (Throwable t) {
					LOGGER.warn("cluster-node {} ({}): discover", nodeId, protocol, t);
				}
			}
		}, intervalMillis / 2, intervalMillis, TimeUnit.MILLISECONDS);
		startReceiver();
	}

	@Override
	public void stop() {
		if (schedule != null) {
			schedule.cancel(false);
			schedule = null;
		}
		clusterManagementConnector.stop();
		super.stop();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * if not processed by the super class, forward the packet to the
	 * {@link #clusterManagementConnector}.
	 */
	@Override
	protected boolean processDatagramFromClusterNetwork(DatagramPacket clusterPacket) throws IOException {
		if (!super.processDatagramFromClusterNetwork(clusterPacket)) {
			LOGGER.trace("cluster-node {} ({}): process datagram from {}, {} bytes", nodeId, protocol,
					clusterPacket.getAddress(), clusterPacket.getLength());
			clusterManagementConnector.processDatagram(clusterPacket);
		}
		return true;
	}

	/**
	 * Process cluster management data.
	 * 
	 * @param clusterData cluster management data
	 */
	protected void processMessageFromClusterManagement(RawData clusterData) {
		final byte[] data = clusterData.getBytes();

		final byte type = data[0];
		if (clusterData.getSize() < 5) {
			// nothing to do
			return;
		}
		InetSocketAddress router = (InetSocketAddress) clusterData.getInetSocketAddress();
		if (type == MAGIC_ID_PING) {
			int foreignNodeId = decodePingPong(data);
			if (nodeId != foreignNodeId) {
				nodesDiscoverer.update(foreignNodeId, router);
				LOGGER.info("cluster-node {} ({}): >update node {} to {}", nodeId, protocol, foreignNodeId, router);
				// reset packet size
				encodePingPong(data, MAGIC_ID_PONG, nodeId);
				RawData outbound = RawData.outbound(data, clusterData.getEndpointContext(), null, false);
				clusterManagementConnector.send(outbound);
				if (clusterHealth != null) {
					clusterHealth.receivingClusterManagementMessage();
					clusterHealth.sendingClusterManagementMessage();
				}
			}
		} else if (type == MAGIC_ID_PONG) {
			int foreignNodeId = decodePingPong(data);
			nodesDiscoverer.update(foreignNodeId, router);
			LOGGER.info("cluster-node {} ({}): <update node {} to {}", nodeId, protocol, foreignNodeId, router);
			if (clusterHealth != null) {
				clusterHealth.receivingClusterManagementMessage();
			}
		}
	}

	/**
	 * Add two values.
	 * 
	 * @param value value, if {@code null} or {@code 0}, don't add the second
	 *            value.
	 * @param add additional value.
	 * @return added value
	 */
	private static Integer add(Integer value, int add) {
		if (value != null && value != 0) {
			return value + add;
		} else {
			return value;
		}
	}

	/**
	 * Decode node-id from {@link #MAGIC_ID_PING} or {@link #MAGIC_ID_PING}
	 * messages.
	 * 
	 * @param data received cluster management data
	 * @return node-id
	 */
	private static int decodePingPong(byte[] data) {
		int nodeId = data[1] & 0xff;
		nodeId |= (data[2] & 0xff) << 8;
		nodeId |= (data[3] & 0xff) << 16;
		nodeId |= (data[4] & 0xff) << 24;
		return nodeId;
	}

	/**
	 * Encode type and node-id.
	 * 
	 * @param data cluster management data to send
	 * @param type {@link #MAGIC_ID_PING} or {@link #MAGIC_ID_PING}
	 * @param nodeId node-id
	 */
	private static void encodePingPong(byte[] data, byte type, int nodeId) {
		data[0] = type;
		data[1] = (byte) (nodeId);
		data[2] = (byte) (nodeId >> 8);
		data[3] = (byte) (nodeId >> 16);
		data[4] = (byte) (nodeId >> 24);
	}

	/**
	 * Interface to get cluster nodes scope.
	 */
	public static interface ClusterNodesDiscover {

		/**
		 * Get cluster configuration.
		 * 
		 * @return cluster configuration
		 */
		DtlsClusterConfig getConfiguration();

		/**
		 * List of addresses of other nodes in the cluster.
		 * 
		 * @return list of other nodes.
		 */
		List<InetSocketAddress> getClusterNodesDiscoverScope();

	}

	/**
	 * Discover manager and provide nodes for cluster.
	 */
	private class NodesDiscoverer implements ClusterNodesProvider {

		/**
		 * Buffer for cluster management message.
		 */
		private final byte[] discoverBuffer = new byte[5];
		/**
		 * Map of node-ids to nodes.
		 */
		private final ConcurrentMap<Integer, Node> nodesById = new ConcurrentHashMap<>();
		/**
		 * Map of management interface addresses to nodes.
		 */
		private final ConcurrentMap<InetSocketAddress, Node> nodesByAddress = new ConcurrentHashMap<>();
		/**
		 * Random for order of messages.
		 */
		private final Random rand = new Random(ClockUtil.nanoRealtime());
		/**
		 * Nanos of next discover operation.
		 */
		private volatile long nextDiscover;

		/**
		 * Create discover manager.
		 */
		private NodesDiscoverer() {
		}

		@Override
		public InetSocketAddress getClusterNode(int nodeId) {
			Node node = nodesById.get(nodeId);
			if (node != null) {
				return node.address;
			} else {
				return null;
			}
		}

		@Override
		public boolean available(InetSocketAddress destinationConnector) {
			return nodesByAddress.containsKey(destinationConnector);
		}

		/**
		 * Update address of node for node-id
		 * 
		 * @param nodeId node-id
		 * @param address cluster management interface address
		 */
		public synchronized void update(int nodeId, InetSocketAddress address) {
			if (DtlsDynClusterConnector.this.nodeId == nodeId) {
				throw new IllegalArgumentException("Own node ID not supported!");
			}
			Node iNode = nodesById.get(nodeId);
			if (iNode == null) {
				iNode = new Node(nodeId, address);
				nodesById.put(nodeId, iNode);
			} else {
				iNode.update(address);
			}
			Node aNode = nodesByAddress.put(address, iNode);
			if (aNode != null && aNode != iNode) {
				nodesById.remove(nodeId, aNode);
			}
		}

		/**
		 * Remove cluster node.
		 * 
		 * @param node remove cluster node.
		 */
		private synchronized void remove(Node node) {
			nodesById.remove(node.nodeId, node);
			nodesByAddress.remove(node.address, node);
		}

		/**
		 * Process node refreshing and discovering.
		 * 
		 * @param clusterManagementConnector connector for cluster management
		 */
		public void process(ClusterManagementConnector clusterManagementConnector) {
			synchronized (rand) {
				if (clusterManagementConnector != null && clusterManagementConnector.isRunning()) {
					long now = ClockUtil.nanoRealtime();
					encodePingPong(discoverBuffer, MAGIC_ID_PING, nodeId);
					boolean discover = refresh(now, clusterManagementConnector) || nodesById.isEmpty()
							|| nextDiscover - now <= 0;
					if (discover && clusterManagementConnector.isRunning()) {
						discover(clusterManagementConnector);
						nextDiscover = ClockUtil.nanoRealtime() + TimeUnit.MILLISECONDS
								.toNanos(discoverScope.getConfiguration().getDiscoverIntervalMillis());
					}
				}
			}
		}

		/**
		 * Refresh cluster nodes.
		 * 
		 * @param now realtime in nanoseconds
		 * @param clusterManagementConnector connector for cluster management
		 * @return {@code true}, if nodes are expired, {@code false}, otherwise.
		 */
		private boolean refresh(long now, ClusterManagementConnector clusterManagementConnector) {
			boolean expired = false;
			long freshTimeNanos = now
					- TimeUnit.MILLISECONDS.toNanos(discoverScope.getConfiguration().getRefreshIntervalMillis());
			long expireTimeNanos = freshTimeNanos
					- TimeUnit.MILLISECONDS.toNanos(discoverScope.getConfiguration().getExpiresMillis());
			List<Node> nodes = new ArrayList<>();
			for (Node node : nodesById.values()) {
				if (node.nodeId == nodeId) {
					// self, not intended to be included
				} else if (node.isBefore(expireTimeNanos)) {
					remove(node);
					expired = true;
				} else if (node.isBefore(freshTimeNanos)) {
					nodes.add(node);
				} else {
					LOGGER.debug("cluster-node {} ({}): keep node {} at {}", nodeId, protocol, node.nodeId,
							node.address);
				}
			}
			while (!nodes.isEmpty()) {
				int pos = rand.nextInt(nodes.size());
				Node node = nodes.remove(pos);
				if (clusterManagementConnector.isRunning()) {
					RawData outbound = RawData.outbound(discoverBuffer, new AddressEndpointContext(node.address),
							messageLoggingCallback, false);
					clusterManagementConnector.send(outbound);
					LOGGER.info("cluster-node {} ({}): refresh node {} at {}", nodeId, protocol, node.nodeId,
							node.address);
					if (clusterHealth != null) {
						clusterHealth.sendingClusterManagementMessage();
					}
				}
			}
			return expired;
		}

		/**
		 * Discover new nodes.
		 * 
		 * @param clusterManagementConnector connector for cluster management
		 */
		private void discover(ClusterManagementConnector clusterManagementConnector) {
			List<InetSocketAddress> scope = discoverScope.getClusterNodesDiscoverScope();
			List<InetSocketAddress> nodes = new ArrayList<>();
			LOGGER.debug("cluster-node {} ({}): own {}", nodeId, protocol, clusterInternalSocketAddress);
			for (InetSocketAddress node : scope) {
				LOGGER.debug("cluster-node {} ({}): discover scope {}", nodeId, protocol, node);
				if (!clusterInternalSocketAddress.equals(node) && !nodesByAddress.containsKey(node)) {
					nodes.add(node);
				}
			}
			while (!nodes.isEmpty()) {
				int pos = rand.nextInt(nodes.size());
				InetSocketAddress node = nodes.remove(pos);
				if (clusterManagementConnector.isRunning()) {
					EndpointContext context;
					if (principal == null) {
						context = new AddressEndpointContext(node);
					} else {
						context = new MapBasedEndpointContext(node, principal, DtlsEndpointContext.KEY_HANDSHAKE_MODE,
								DtlsEndpointContext.HANDSHAKE_MODE_FORCE_FULL);
					}
					RawData outbound = RawData.outbound(discoverBuffer, context, messageLoggingCallback, false);
					clusterManagementConnector.send(outbound);
					LOGGER.info("cluster-node {} ({}):  discover {}", nodeId, protocol, node);
					if (clusterHealth != null) {
						clusterHealth.sendingClusterManagementMessage();
					}
				}
			}
		}
	}

	/**
	 * Cluster node.
	 */
	private static class Node {

		/**
		 * Node-id.
		 */
		private final int nodeId;
		/**
		 * Cluster management interface address of node.
		 */
		private InetSocketAddress address;
		/**
		 * Realtime in nanoseconds of last address update.
		 */
		private long time;

		/**
		 * Create node.
		 * 
		 * @param nodeId node-id.
		 * @param address cluster management interface address
		 */
		private Node(int nodeId, InetSocketAddress address) {
			this.nodeId = nodeId;
			update(address);
		}

		/**
		 * Update address and usage time.
		 * 
		 * @param address cluster management interface address
		 */
		private synchronized void update(InetSocketAddress address) {
			this.address = address;
			this.time = ClockUtil.nanoRealtime();
		}

		/**
		 * Test, if provided nano time is before the last usage.
		 * 
		 * @param timeNanos realtime in nanoseconds
		 * @return {@code true}, if provided nano time is before last usage,
		 *         {@code false}, otherwise.
		 */
		private synchronized boolean isBefore(long timeNanos) {
			return timeNanos - time > 0;
		}
	}

	/**
	 * Cluster management connector.
	 */
	private static interface ClusterManagementConnector extends Connector {

		/**
		 * Connector is running.
		 * 
		 * @return {@code true}, if running, {@code false}, otherwise.
		 */
		boolean isRunning();

		/**
		 * Process datagram.
		 * 
		 * @param datagram datagram to process
		 */
		void processDatagram(DatagramPacket datagram);

	}

	/**
	 * Cluster management connector using UDP.
	 */
	private static class ClusterManagementUdpConnector extends UDPConnector implements ClusterManagementConnector {

		private final DatagramSocket socket;

		public ClusterManagementUdpConnector(InetSocketAddress bindAddress, DatagramSocket socket) {
			super(bindAddress);
			this.socket = socket;
		}

		@Override
		public synchronized void start() throws IOException {
			if (isRunning())
				return;
			init(socket);
		}

		@Override
		public boolean isRunning() {
			return running;
		}

		@Override
		public void processDatagram(DatagramPacket datagram) {
			super.processDatagram(datagram);
		}

	}

	/**
	 * Cluster management connector using DTLS.
	 */
	private static class ClusterManagementDtlsConnector extends DTLSConnector implements ClusterManagementConnector {

		private final DatagramSocket socket;

		public ClusterManagementDtlsConnector(DtlsConnectorConfig configuration, DatagramSocket socket) {
			super(configuration);
			this.socket = socket;
		}

		@Override
		protected void start(InetSocketAddress bindAddress) throws IOException {
			if (isRunning()) {
				return;
			}
			init(bindAddress, socket, config.getMaxTransmissionUnit());
		}

		@Override
		public void processDatagram(DatagramPacket datagram) {
			super.processDatagram(datagram, (InetSocketAddress) datagram.getSocketAddress());
		}

	}

}
