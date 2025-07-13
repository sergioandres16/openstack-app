// PUCP Cloud Orchestrator - Slice Creation JavaScript

let sliceData = {
    nodes: [],
    networks: []
};

let editingNodeIndex = -1;
let editingNetworkIndex = -1;

$(document).ready(function() {
    // Inicializar
    initializeTopologySelector();
    initializeFlavorSelector();
    
    // Event listeners
    $('#generateTopology').click(generateTopology);
    $('#customizeNodes').click(toggleCustomization);
    $('#addNode').click(showNodeModal);
    $('#addNetwork').click(showNetworkModal);
    $('#saveNodeConfig').click(saveNodeConfig);
    $('#saveNetworkConfig').click(saveNetworkConfig);
    $('#previewSlice').click(showPreview);
    $('#sliceForm').submit(submitSlice);
    
    // Actualizar detalles del flavor cuando cambia
    $('#nodeFlavor').change(updateFlavorDetails);
    $('#topologyType').change(updateTopologyInfo);
    $('#nodeCount').change(validateNodeCount);
});

function initializeTopologySelector() {
    const topologyType = $('#topologyType').val();
    updateTopologyInfo();
}

function initializeFlavorSelector() {
    updateFlavorDetails();
}

function updateTopologyInfo() {
    const topologyType = $('#topologyType').val();
    
    // Actualizar limits del node count
    const topologies = {
        'linear': {min: 2, max: 10, name: 'Topología Lineal'},
        'mesh': {min: 3, max: 8, name: 'Topología Malla'},
        'tree': {min: 3, max: 15, name: 'Topología Árbol'},
        'ring': {min: 3, max: 12, name: 'Topología Anillo'},
        'bus': {min: 3, max: 20, name: 'Topología Bus'}
    };
    
    const topology = topologies[topologyType];
    if (topology) {
        $('#nodeCount').attr('min', topology.min).attr('max', topology.max);
        $('#nodeCount').next('.form-text').text(`Mínimo: ${topology.min}, Máximo: ${topology.max}`);
    }
}

function validateNodeCount() {
    const nodeCount = parseInt($('#nodeCount').val());
    const min = parseInt($('#nodeCount').attr('min'));
    const max = parseInt($('#nodeCount').attr('max'));
    
    if (nodeCount < min) {
        $('#nodeCount').val(min);
    } else if (nodeCount > max) {
        $('#nodeCount').val(max);
    }
}

function updateFlavorDetails() {
    const selectedOption = $('#nodeFlavor option:selected');
    const vcpus = selectedOption.data('vcpus');
    const ram = selectedOption.data('ram');
    const disk = selectedOption.data('disk');
    
    $('#flavorDetails').text(`${vcpus} vCPU, ${ram}MB RAM, ${disk}GB Disco`);
}

function generateTopology() {
    const topologyType = $('#topologyType').val();
    const nodeCount = parseInt($('#nodeCount').val());
    
    showSpinner('Generando topología...');
    
    $.ajax({
        url: '/api/topology/generate',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            topology: topologyType,
            node_count: nodeCount
        }),
        success: function(response) {
            hideSpinner();
            if (response.success) {
                sliceData = response.topology;
                renderNodes();
                renderNetworks();
                showCustomization();
                showAlert('success', 'Topología generada exitosamente');
            } else {
                showAlert('error', response.error || 'Error generando topología');
            }
        },
        error: function(xhr) {
            hideSpinner();
            const error = xhr.responseJSON?.error || 'Error de conexión';
            showAlert('error', error);
        }
    });
}

function toggleCustomization() {
    if (sliceData.nodes.length === 0) {
        // Inicializar con nodos básicos
        const nodeCount = parseInt($('#nodeCount').val()) || 3;
        for (let i = 0; i < nodeCount; i++) {
            sliceData.nodes.push({
                name: `node-${i + 1}`,
                image: 'ubuntu-20.04',
                flavor: 'small',
                internet_access: i === 0
            });
        }
        
        // Agregar red básica
        sliceData.networks.push({
            name: 'data-network',
            cidr: '192.168.100.0/24',
            network_type: 'data'
        });
    }
    
    renderNodes();
    renderNetworks();
    showCustomization();
}

function showCustomization() {
    $('#nodesCard, #networksCard').show();
    $('#customizeNodes').text('Ocultar Personalización');
}

function renderNodes() {
    const nodesList = $('#nodesList');
    nodesList.empty();
    
    sliceData.nodes.forEach((node, index) => {
        const nodeCard = createNodeCard(node, index);
        nodesList.append(nodeCard);
    });
    
    updateResourceSummary();
}

function createNodeCard(node, index) {
    return $(`
        <div class="node-item" data-index="${index}">
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <h6><i class="fas fa-server"></i> ${node.name}</h6>
                    <div class="row">
                        <div class="col-md-4">
                            <small><strong>Imagen:</strong> ${node.image}</small>
                        </div>
                        <div class="col-md-4">
                            <small><strong>Capacidad:</strong> ${getFlavorDescription(node.flavor)}</small>
                        </div>
                        <div class="col-md-4">
                            <small><strong>Internet:</strong> ${node.internet_access ? 'Sí' : 'No'}</small>
                        </div>
                    </div>
                    ${node.management_ip ? `<small><strong>IP Gestión:</strong> ${node.management_ip}</small>` : ''}
                </div>
                <div class="btn-group-vertical btn-group-sm">
                    <button type="button" class="btn btn-outline-primary edit-node-btn" data-index="${index}">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button type="button" class="btn btn-outline-danger remove-node-btn" data-index="${index}">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        </div>
    `);
}

function renderNetworks() {
    const networksList = $('#networksList');
    networksList.empty();
    
    sliceData.networks.forEach((network, index) => {
        const networkCard = createNetworkCard(network, index);
        networksList.append(networkCard);
    });
}

function createNetworkCard(network, index) {
    return $(`
        <div class="network-item" data-index="${index}">
            <div class="d-flex justify-content-between align-items-start">
                <div class="flex-grow-1">
                    <h6><i class="fas fa-network-wired"></i> ${network.name}</h6>
                    <div class="row">
                        <div class="col-md-4">
                            <small><strong>CIDR:</strong> ${network.cidr}</small>
                        </div>
                        <div class="col-md-4">
                            <small><strong>Tipo:</strong> ${network.network_type}</small>
                        </div>
                        <div class="col-md-4">
                            <small><strong>Internet:</strong> ${network.internet_access ? 'Sí' : 'No'}</small>
                        </div>
                    </div>
                    ${network.gateway ? `<small><strong>Gateway:</strong> ${network.gateway}</small>` : ''}
                </div>
                <div class="btn-group-vertical btn-group-sm">
                    <button type="button" class="btn btn-outline-success edit-network-btn" data-index="${index}">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button type="button" class="btn btn-outline-danger remove-network-btn" data-index="${index}">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        </div>
    `);
}

function getFlavorDescription(flavorId) {
    const flavors = {
        'nano': '1 vCPU, 512MB, 1GB',
        'micro': '1 vCPU, 1GB, 5GB',
        'small': '1 vCPU, 1.5GB, 10GB',
        'medium': '2 vCPU, 2.5GB, 20GB',
        'large': '4 vCPU, 6GB, 40GB'
    };
    return flavors[flavorId] || flavorId;
}

function updateResourceSummary() {
    const flavors = {
        'nano': {vcpus: 1, ram: 512, disk: 1},
        'micro': {vcpus: 1, ram: 1024, disk: 5},
        'small': {vcpus: 1, ram: 1536, disk: 10},
        'medium': {vcpus: 2, ram: 2560, disk: 20},
        'large': {vcpus: 4, ram: 6144, disk: 40}
    };
    
    let totalVcpus = 0, totalRam = 0, totalDisk = 0;
    
    sliceData.nodes.forEach(node => {
        const flavor = flavors[node.flavor] || flavors['small'];
        totalVcpus += flavor.vcpus;
        totalRam += flavor.ram;
        totalDisk += flavor.disk;
    });
    
    const summary = `
        <div class="resource-summary">
            <strong>Recursos Totales:</strong>
            ${totalVcpus} vCPUs, ${(totalRam / 1024).toFixed(1)}GB RAM, ${totalDisk}GB Disco
        </div>
    `;
    
    $('#nodesList').append(summary);
}

// Event handlers para botones dinámicos
$(document).on('click', '.edit-node-btn', function() {
    editingNodeIndex = $(this).data('index');
    const node = sliceData.nodes[editingNodeIndex];
    populateNodeModal(node);
    $('#nodeConfigModal').modal('show');
});

$(document).on('click', '.remove-node-btn', function() {
    const index = $(this).data('index');
    sliceData.nodes.splice(index, 1);
    renderNodes();
});

$(document).on('click', '.edit-network-btn', function() {
    editingNetworkIndex = $(this).data('index');
    const network = sliceData.networks[editingNetworkIndex];
    populateNetworkModal(network);
    $('#networkConfigModal').modal('show');
});

$(document).on('click', '.remove-network-btn', function() {
    const index = $(this).data('index');
    sliceData.networks.splice(index, 1);
    renderNetworks();
});

function showNodeModal() {
    editingNodeIndex = -1;
    populateNodeModal({
        name: `node-${sliceData.nodes.length + 1}`,
        image: 'ubuntu-20.04',
        flavor: 'small',
        internet_access: false,
        management_ip: ''
    });
    $('#nodeConfigModal').modal('show');
}

function populateNodeModal(node) {
    $('#nodeName').val(node.name || '');
    $('#nodeImage').val(node.image || 'ubuntu-20.04');
    $('#nodeFlavor').val(node.flavor || 'small');
    $('#internetAccess').prop('checked', node.internet_access || false);
    $('#managementIp').val(node.management_ip || '');
    updateFlavorDetails();
}

function saveNodeConfig() {
    const nodeConfig = {
        name: $('#nodeName').val(),
        image: $('#nodeImage').val(),
        flavor: $('#nodeFlavor').val(),
        internet_access: $('#internetAccess').is(':checked'),
        management_ip: $('#managementIp').val()
    };
    
    if (!nodeConfig.name) {
        showAlert('error', 'El nombre del nodo es requerido');
        return;
    }
    
    if (editingNodeIndex >= 0) {
        sliceData.nodes[editingNodeIndex] = nodeConfig;
    } else {
        sliceData.nodes.push(nodeConfig);
    }
    
    renderNodes();
    $('#nodeConfigModal').modal('hide');
}

function showNetworkModal() {
    editingNetworkIndex = -1;
    populateNetworkModal({
        name: `network-${sliceData.networks.length + 1}`,
        cidr: `192.168.${100 + sliceData.networks.length}.0/24`,
        network_type: 'data',
        internet_access: false,
        gateway: ''
    });
    $('#networkConfigModal').modal('show');
}

function populateNetworkModal(network) {
    $('#networkName').val(network.name || '');
    $('#networkCidr').val(network.cidr || '');
    $('#networkType').val(network.network_type || 'data');
    $('#networkInternet').prop('checked', network.internet_access || false);
    $('#networkGateway').val(network.gateway || '');
}

function saveNetworkConfig() {
    const networkConfig = {
        name: $('#networkName').val(),
        cidr: $('#networkCidr').val(),
        network_type: $('#networkType').val(),
        internet_access: $('#networkInternet').is(':checked'),
        gateway: $('#networkGateway').val()
    };
    
    if (!networkConfig.name || !networkConfig.cidr) {
        showAlert('error', 'Nombre y CIDR son requeridos');
        return;
    }
    
    if (editingNetworkIndex >= 0) {
        sliceData.networks[editingNetworkIndex] = networkConfig;
    } else {
        sliceData.networks.push(networkConfig);
    }
    
    renderNetworks();
    $('#networkConfigModal').modal('hide');
}

function showPreview() {
    const preview = generatePreviewHTML();
    $('#slicePreview').html(preview);
    $('#previewCard').show();
}

function generatePreviewHTML() {
    return `
        <div class="row">
            <div class="col-md-6">
                <h6><i class="fas fa-server"></i> Nodos (${sliceData.nodes.length})</h6>
                <div class="list-group">
                    ${sliceData.nodes.map(node => `
                        <div class="list-group-item">
                            <strong>${node.name}</strong><br>
                            <small>${node.image} | ${getFlavorDescription(node.flavor)}</small>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="col-md-6">
                <h6><i class="fas fa-network-wired"></i> Redes (${sliceData.networks.length})</h6>
                <div class="list-group">
                    ${sliceData.networks.map(network => `
                        <div class="list-group-item">
                            <strong>${network.name}</strong><br>
                            <small>${network.cidr} | ${network.network_type}</small>
                        </div>
                    `).join('')}
                </div>
            </div>
        </div>
    `;
}

function submitSlice(e) {
    e.preventDefault();
    
    if (sliceData.nodes.length === 0) {
        showAlert('error', 'Debe agregar al menos un nodo');
        return;
    }
    
    const formData = {
        name: $('#sliceName').val(),
        description: $('#description').val(),
        infrastructure: $('#infrastructure').val(),
        nodes: sliceData.nodes,
        networks: sliceData.networks
    };
    
    showSpinner('Creando slice...');
    
    $.ajax({
        url: '/slice/create',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(formData),
        success: function(response) {
            hideSpinner();
            if (response.success) {
                showAlert('success', 'Slice creado exitosamente');
                setTimeout(() => {
                    window.location.href = '/slices';
                }, 1500);
            } else {
                showAlert('error', response.error || 'Error creando slice');
            }
        },
        error: function(xhr) {
            hideSpinner();
            const error = xhr.responseJSON?.error || 'Error de conexión';
            showAlert('error', error);
        }
    });
}

function showSpinner(message) {
    $('#progressMessage').text(message);
    $('#progressModal').modal('show');
}

function hideSpinner() {
    $('#progressModal').modal('hide');
}

function showAlert(type, message) {
    const alertClass = type === 'error' ? 'alert-danger' : 'alert-success';
    const icon = type === 'error' ? 'fa-exclamation-triangle' : 'fa-check-circle';
    
    const alert = $(`
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
            <i class="fas ${icon}"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `);
    
    $('.container').prepend(alert);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        alert.alert('close');
    }, 5000);
}