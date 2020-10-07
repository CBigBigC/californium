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
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.WipAPI;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.NodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.SessionCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DTLS cluster connector.
 * 
 * Forwards foreign cid records to other connectors.
 * 
 * @since 2.5
 */
@WipAPI
public class DtlsClusterConnector extends DTLSConnector {

	private static final Logger LOGGER = LoggerFactory.getLogger(DtlsClusterConnector.class);

	/**
	 * Datagram offset for messages forwarded to other nodes.
	 */
	protected static final int DATAGRAM_OFFSET = 20;
	/**
	 * Type of incoming forwarded messages.
	 */
	private static final byte MAGIC_INCOMING = (byte) 63;
	/**
	 * Type of outgoing forwarded messages.
	 */
	private static final byte MAGIC_OUTGOING = (byte) 62;

	/**
	 * Node CID generator to extract node-id from CID and retrieve own node-id.
	 */
	private final NodeConnectionIdGenerator nodeCidGenerator;
	/**
	 * Node ID within cluster.
	 */
	protected final int nodeId;
	/**
	 * Start receiver for cluster internal communication on
	 * {@link #init(InetSocketAddress, DatagramSocket, Integer)}.
	 */
	protected final boolean startReceiver;
	/**
	 * DTLS cluster health statistic.
	 */
	protected final DtlsClusterHealth clusterHealth;
	/**
	 * Socket address for cluster internal communication.
	 */
	protected final InetSocketAddress clusterInternalSocketAddress;
	/**
	 * Datagram socket for cluster internal communication.
	 */
	protected volatile DatagramSocket clusterInternalSocket;
	/**
	 * Nodes provider for cluster.
	 */
	protected ClusterNodesProvider nodesProvider;

	/**
	 * Create dtls connector with cluster support.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterInternalSocketAddress Socket address for cluster internal
	 *            communication
	 * @param nodes nodes provider
	 */
	public DtlsClusterConnector(DtlsConnectorConfig configuration, InetSocketAddress clusterInternalSocketAddress,
			ClusterNodesProvider nodes) {
		this(configuration, clusterInternalSocketAddress, nodes, null);
	}

	/**
	 * Create dtls connector with cluster support and session cache.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterInternalSocketAddress Socket address for cluster internal
	 *            communication
	 * @param nodes nodes provider
	 * @param sessionCache session cache
	 */
	public DtlsClusterConnector(DtlsConnectorConfig configuration, InetSocketAddress clusterInternalSocketAddress,
			ClusterNodesProvider nodes, SessionCache sessionCache) {
		this(configuration, clusterInternalSocketAddress, sessionCache, true);
		this.nodesProvider = nodes;
	}

	/**
	 * Create dtls connector with cluster support and session cache, without
	 * receiver threads for cluster internal communication.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterInternalSocketAddress cluster internal socket address
	 * @param sessionCache session cache
	 */
	protected DtlsClusterConnector(DtlsConnectorConfig configuration, InetSocketAddress clusterInternalSocketAddress,
			SessionCache sessionCache) {
		this(configuration, clusterInternalSocketAddress, sessionCache, false);
	}

	/**
	 * Create dtls connector with cluster support and session cache.
	 * 
	 * @param configuration dtls configuration
	 * @param clusterInternalSocketAddress cluster internal socket address
	 * @param sessionCache session cache
	 * @param startReceiver start receiver threads for cluster internal
	 *            communication
	 */
	private DtlsClusterConnector(DtlsConnectorConfig configuration, InetSocketAddress clusterInternalSocketAddress,
			SessionCache sessionCache, boolean startReceiver) {
		super(configuration, sessionCache);
		this.nodeCidGenerator = getNodeConnectionIdGenerator();
		this.nodeId = nodeCidGenerator.getNodeId();
		if (clusterInternalSocketAddress == null) {
			throw new IllegalArgumentException("Local cluster socker address missing for " + nodeId + "!");
		}
		this.clusterInternalSocketAddress = clusterInternalSocketAddress;
		this.clusterHealth = (health instanceof DtlsClusterHealth) ? (DtlsClusterHealth) health : null;
		this.startReceiver = startReceiver;
		LOGGER.info("cluster-node {}: on {}", nodeId, StringUtil.toDisplayString(clusterInternalSocketAddress));
	}

	/**
	 * Get node's cid generator.
	 * 
	 * @return node's cid generator.
	 * @throws IllegalArgumentException if cid generator is not provided, or the
	 *             cid generator only supports, but doesn't use cids, or the cid
	 *             generator is no {@link NodeConnectionIdGenerator}.
	 */
	private NodeConnectionIdGenerator getNodeConnectionIdGenerator() {
		if (connectionIdGenerator == null) {
			throw new IllegalArgumentException("CID generator missing!");
		} else if (!connectionIdGenerator.useConnectionId()) {
			throw new IllegalArgumentException("CID not used!");
		} else if (!(connectionIdGenerator instanceof NodeConnectionIdGenerator)) {
			throw new IllegalArgumentException("CID generator not supports nodes!");
		}
		return (NodeConnectionIdGenerator) connectionIdGenerator;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Creates a {@link DtlsClusterHealthLogger}.
	 */
	@Override
	protected DtlsHealth createDefaultHealthHandler(DtlsConnectorConfig configuration) {
		return new DtlsClusterHealthLogger(configuration.getLoggingTag());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Creates also socket and threads for cluster internal communication. The
	 * threads are only create, if {@link #startReceiver} is {@code true}.
	 */
	@Override
	protected void init(InetSocketAddress bindAddress, DatagramSocket socket, Integer mtu) throws IOException {
		try {
			clusterInternalSocket = new DatagramSocket(clusterInternalSocketAddress);
		} catch (IOException ex) {
			LOGGER.error("cluster-node {}: management-interface {} failed!", nodeId,
					StringUtil.toDisplayString(clusterInternalSocketAddress));
			throw ex;
		}
		super.init(bindAddress, socket, mtu);
		if (startReceiver) {
			startReceiver();
		}
	}

	/**
	 * Start receiver threads for cluster internal communication.
	 * 
	 * After starting the threads, the {@link #clusterInternalSocket} may be
	 * locked by these threads calling
	 * {@link DatagramSocket#receive(DatagramPacket)}.
	 */
	protected void startReceiver() {
		int receiverThreadCount = config.getReceiverThreadCount();
		for (int i = 0; i < receiverThreadCount; i++) {
			Worker receiver = new Worker(
					"DTLS-Cluster-" + nodeId + "-Receiver-" + i + "-" + clusterInternalSocketAddress) {

				private final byte[] receiverBuffer = new byte[inboundDatagramBufferSize + DATAGRAM_OFFSET];
				private final DatagramPacket clusterPacket = new DatagramPacket(receiverBuffer, receiverBuffer.length);

				@Override
				public void doWork() throws Exception {
					clusterPacket.setData(receiverBuffer);
					clusterInternalSocket.receive(clusterPacket);
					processDatagramFromClusterNetwork(clusterPacket);
				}
			};
			receiver.setDaemon(true);
			receiver.start();
			receiverThreads.add(receiver);
		}
		LOGGER.info("cluster-node {}: started {}", nodeId, clusterInternalSocket.getLocalSocketAddress());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Stop also socket and threads for cluster internal communication.
	 */
	@Override
	public void stop() {
		super.stop();
		clusterInternalSocket.close();
	}

	/**
	 * Process received cluster internal message.
	 * 
	 * @param clusterPacket cluster internal message
	 * @return {@code true}, if processing is completed, {@code false}, if not.
	 * @throws IOException if an io-error occurred.
	 */
	protected boolean processDatagramFromClusterNetwork(DatagramPacket clusterPacket) throws IOException {

		final byte type = clusterPacket.getData()[clusterPacket.getOffset()];
		if (type != MAGIC_INCOMING && type != MAGIC_OUTGOING) {
			return false;
		}
		if (clusterPacket.getLength() < 5) {
			// nothing to do
			return true;
		}
		InetSocketAddress router = (InetSocketAddress) clusterPacket.getSocketAddress();
		DatagramPacket packet = decode(clusterPacket);
		if (packet == null) {
			// nothing to do
			return true;
		}
		if (type == MAGIC_INCOMING) {
			LOGGER.trace("cluster-node {}: received forwarded message", nodeId);
			super.processDatagram(packet, router);
			if (clusterHealth != null) {
				clusterHealth.processForwardedMessage();
			}
		} else if (type == MAGIC_OUTGOING) {
			LOGGER.trace("cluster-node {}: received backwarded outgoing message", nodeId);
			super.sendNextDatagramOverNetwork(packet);
			if (clusterHealth != null) {
				clusterHealth.sendBackwardedMessage();
			}
		}
		return true;
	}

	/**
	 * Send cluster internal message.
	 * 
	 * @param clusterPacket cluster internal message
	 * @throws IOException if an io-error occurred.
	 */
	protected void sendDatagramToClusterNetwork(DatagramPacket clusterPacket) throws IOException {
		clusterInternalSocket.send(clusterPacket);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Test for CID records and forward foreign records to other nodes.
	 */
	@Override
	protected void processDatagram(DatagramPacket packet, InetSocketAddress router) {
		int offset = packet.getOffset();
		int length = packet.getLength();
		byte[] data = packet.getData();
		InetSocketAddress source = (InetSocketAddress) packet.getSocketAddress();
		if (data[offset] == ContentType.TLS12_CID.getCode()) {
			if (length > Record.RECORD_HEADER_BYTES) {
				DatagramReader reader = new DatagramReader(data, offset, length);
				ConnectionId cid = Record.readConnectionIdFromReader(reader, connectionIdGenerator);
				if (cid != null) {
					int incomingNodeId = nodeCidGenerator.getNodeId(cid);
					if (nodeId != incomingNodeId) {
						LOGGER.trace("cluster-node {}: received foreign message for {} from {}", nodeId, incomingNodeId,
								source);
						InetSocketAddress clusterNode = nodesProvider.getClusterNode(incomingNodeId);
						if (clusterNode != null) {
							DatagramPacket clusterPacket = encode(packet, MAGIC_INCOMING);
							clusterPacket.setSocketAddress(clusterNode);
							try {
								LOGGER.trace("cluster-node {}: forwards received message from {} to {}, {} bytes",
										nodeId, source, clusterNode, length);
								sendDatagramToClusterNetwork(clusterPacket);
								if (clusterHealth != null) {
									clusterHealth.forwardMessage();
								}
								return;
							} catch (IOException e) {
								LOGGER.info("cluster-node {}: send error:", nodeId, e);
							}
						} else {
							LOGGER.debug(
									"cluster-node {}: received foreign message from {} for unknown node {}, {} bytes, dropping.",
									nodeId, source, incomingNodeId, length);
							if (clusterHealth != null) {
								clusterHealth.dropForwardMessage();
							} else {
								health.receivingRecord(true);
							}
						}
					} else {
						LOGGER.trace("cluster-node {}: received own message from {}, {} bytes", nodeId, source, length);
					}
				} else {
					LOGGER.debug("cluster-node {}: received broken CID message from {}", nodeId, source);
				}
			} else {
				LOGGER.debug("cluster-node {}: received too short CID message from {}", nodeId, source);
			}
		} else {
			LOGGER.trace("cluster-node {}: received no CID message from {}, {} bytes.", nodeId, source, length);
		}
		super.processDatagram(packet, null);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * For {@link Record#getRouter()} destinations, backwards massage to
	 * original receiving connector (router).
	 */
	@Override
	protected void sendRecord(Record record) throws IOException {
		InetSocketAddress destination = record.getPeerAddress();
		InetSocketAddress router = record.getRouter();
		if (router != null) {
			if (nodesProvider.available(router)) {
				byte[] recordBytes = record.toByteArray();
				int length = recordBytes.length;
				byte[] datagramBytes = new byte[length + DATAGRAM_OFFSET];
				System.arraycopy(recordBytes, 0, datagramBytes, DATAGRAM_OFFSET, length);
				DatagramPacket datagram = new DatagramPacket(datagramBytes, DATAGRAM_OFFSET, length, destination);
				LOGGER.trace("cluster-node {}: backwards send message for {} to {}, {} bytes", nodeId, destination,
						router, length);
				DatagramPacket clusterPacket = encode(datagram, MAGIC_OUTGOING);
				clusterPacket.setSocketAddress(router);
				sendDatagramToClusterNetwork(clusterPacket);
				if (clusterHealth != null) {
					clusterHealth.backwardMessage();
				}
			} else {
				if (clusterHealth != null) {
					clusterHealth.dropBackwardMessage();
				} else {
					health.sendingRecord(true);
				}
			}
		} else {
			LOGGER.trace("cluster-node {}: sends message to {}, {} bytes", nodeId, destination, record.size());
			super.sendRecord(record);
		}
	}

	/**
	 * Encode message for cluster internal communication.
	 * 
	 * Add original source address at message head.
	 * 
	 * @param packet received message
	 * @param direction direction of message. Values are {@link #MAGIC_INCOMING}
	 *            or {@link #MAGIC_OUTGOING}
	 * @return encoded message with original source address
	 * @see #decode(DatagramPacket)
	 */
	private DatagramPacket encode(DatagramPacket packet, byte direction) {
		InetAddress source = packet.getAddress();
		byte[] data = packet.getData();
		int offset = packet.getOffset();
		int length = packet.getLength();
		if (offset != DATAGRAM_OFFSET) {
			System.arraycopy(data, offset, data, DATAGRAM_OFFSET, length);
		}
		byte[] address = source.getAddress();
		data[0] = direction;
		data[1] = (byte) address.length;
		data[2] = (byte) packet.getPort();
		data[3] = (byte) (packet.getPort() >> 8);
		System.arraycopy(address, 0, data, 4, address.length);
		packet.setData(data, 0, length + DATAGRAM_OFFSET);
		return packet;
	}

	/**
	 * Decode message from cluster internal communication.
	 * 
	 * @param packet message with original source address encoded at head.
	 * @return message with decoded original source address
	 * @see #encode(DatagramPacket, byte)
	 */
	private DatagramPacket decode(DatagramPacket packet) {
		byte[] data = packet.getData();
		int offset = packet.getOffset();
		int length = packet.getLength();
		if (offset == 0) {
			int addressLength = data[1] & 0xff;
			int port = (data[2] & 0xff) | ((data[3] & 0xff) << 8);
			byte[] address = Arrays.copyOfRange(data, 4, addressLength + 4);
			try {
				InetAddress iaddr = InetAddress.getByAddress(address);
				packet.setAddress(iaddr);
				packet.setPort(port);
				packet.setData(data, DATAGRAM_OFFSET, length - DATAGRAM_OFFSET);
				return packet;
			} catch (UnknownHostException e) {
			}
		} else {
			LOGGER.debug("cluster-node {}: packet {} bytes, misformed!", nodeId, length);
		}
		return null;
	}

	/**
	 * Cluster nodes provider. Maintaining internal addresses of nodes.
	 */
	public static interface ClusterNodesProvider {

		/**
		 * Get address for node.
		 * 
		 * @param nodeId node id of node
		 * @return internal address of node. {@code null}, if not available.
		 */
		InetSocketAddress getClusterNode(int nodeId);

		/**
		 * Check, if address to backward message is still available.
		 * 
		 * @param destinationConnector address of destination connector.
		 * @return {@code true}, if destination is still available,
		 *         {@code false}, if not.
		 */
		boolean available(InetSocketAddress destinationConnector);
	}
}
