// PUCP Cloud Orchestrator - Slice Creation for OpenStack

let openstackFlavors = [];
let openstackImages = [];
let publicNetworks = [];

$(document).ready(function() {
    // Inicializar carga de datos de OpenStack
    loadOpenStackData();
    
    // Event listeners
    $('#vmFlavor').change(updateFlavorDetails);
    $('#vmImage').change(updateImageDetails);
    $('#nodeCount').change(updateResourceSummary);
    $('#toggleCloudInit').click(toggleCloudInitSection);
    $('#previewSlice').click(showSlicePreview);
    $('#sliceForm').submit(submitSlice);
    
    // Auto-generar prefijo basado en nombre del slice
    $('#sliceName').on('input', function() {
        const sliceName = $(this).val().toLowerCase();
        if (sliceName && !$('#vmNamePrefix').val()) {
            $('#vmNamePrefix').val(sliceName.replace(/[^a-z0-9]/g, ''));
        }
    });
    
    // Auto-generar nombre de red basado en slice
    $('#sliceName').on('input', function() {
        const sliceName = $(this).val().toLowerCase();
        if (sliceName && !$('#sliceNetworkName').val()) {
            $('#sliceNetworkName').val(sliceName.replace(/[^a-z0-9]/g, '') + '-net');
        }
    });
});

function loadOpenStackData() {
    showAlert('info', 'Cargando datos de OpenStack...');
    
    // Cargar flavors, imágenes y redes en paralelo
    Promise.all([
        loadFlavors(),
        loadImages(),
        loadPublicNetworks()
    ]).then(() => {
        showAlert('success', 'Datos de OpenStack cargados correctamente');
        updateResourceSummary();
    }).catch(error => {
        console.error('Error loading OpenStack data:', error);
        showAlert('error', 'Error cargando datos de OpenStack: ' + error.message);
    });
}

function loadFlavors() {
    return new Promise((resolve, reject) => {
        $.ajax({
            url: '/api/openstack/flavors',
            method: 'GET',
            success: function(response) {
                if (response.success) {
                    openstackFlavors = response.flavors;
                    populateFlavorSelect();
                    resolve();
                } else {
                    reject(new Error(response.error || 'Error cargando flavors'));
                }
            },
            error: function(xhr) {
                reject(new Error(xhr.responseJSON?.error || 'Error de conexión al cargar flavors'));
            }
        });
    });
}

function loadImages() {
    return new Promise((resolve, reject) => {
        $.ajax({
            url: '/api/openstack/images',
            method: 'GET',
            success: function(response) {
                if (response.success) {
                    openstackImages = response.images;
                    populateImageSelect();
                    resolve();
                } else {
                    reject(new Error(response.error || 'Error cargando imágenes'));
                }
            },
            error: function(xhr) {
                reject(new Error(xhr.responseJSON?.error || 'Error de conexión al cargar imágenes'));
            }
        });
    });
}

function loadPublicNetworks() {
    return new Promise((resolve, reject) => {
        $.ajax({
            url: '/api/openstack/public-networks',
            method: 'GET',
            success: function(response) {
                if (response.success) {
                    publicNetworks = response.networks;
                    resolve();
                } else {
                    reject(new Error(response.error || 'Error cargando redes públicas'));
                }
            },
            error: function(xhr) {
                reject(new Error(xhr.responseJSON?.error || 'Error de conexión al cargar redes'));
            }
        });
    });
}

function populateFlavorSelect() {
    const $select = $('#vmFlavor');
    $select.empty();
    $select.append('<option value="">Seleccione un flavor...</option>');
    
    openstackFlavors.forEach(flavor => {
        const option = $(`<option value="${flavor.id}">${flavor.name} - ${flavor.vcpus} vCPUs, ${Math.round(flavor.ram/1024)}GB RAM, ${flavor.disk}GB Disk</option>`);
        option.data('flavor', flavor);
        $select.append(option);
    });
}

function populateImageSelect() {
    const $select = $('#vmImage');
    $select.empty();
    $select.append('<option value="">Seleccione una imagen...</option>');
    
    // Filtrar solo imágenes activas
    const activeImages = openstackImages.filter(img => img.status === 'active');
    
    activeImages.forEach(image => {
        const sizeGB = image.size ? Math.round(image.size / (1024 * 1024 * 1024)) : 'N/A';
        const option = $(`<option value="${image.id}">${image.name} (${sizeGB}GB)</option>`);
        option.data('image', image);
        $select.append(option);
    });
}

function updateFlavorDetails() {
    const selectedOption = $('#vmFlavor option:selected');
    const flavor = selectedOption.data('flavor');
    
    if (flavor) {
        const details = `${flavor.vcpus} vCPUs, ${Math.round(flavor.ram/1024)}GB RAM, ${flavor.disk}GB Disk`;
        $('#flavorDetails').text(details);
        updateResourceSummary();
    } else {
        $('#flavorDetails').text('Seleccione un flavor para ver detalles');
    }
}

function updateImageDetails() {
    const selectedOption = $('#vmImage option:selected');
    const image = selectedOption.data('image');
    
    if (image) {
        const sizeGB = image.size ? Math.round(image.size / (1024 * 1024 * 1024)) : 'N/A';
        const details = `${image.name} - ${sizeGB}GB, ${image.status}`;
        $('#imageDetails').text(details);
    } else {
        $('#imageDetails').text('Seleccione una imagen para ver detalles');
    }
}

function updateResourceSummary() {
    const nodeCount = parseInt($('#nodeCount').val()) || 0;
    const selectedOption = $('#vmFlavor option:selected');
    const flavor = selectedOption.data('flavor');
    
    if (flavor && nodeCount > 0) {
        const totalVcpus = flavor.vcpus * nodeCount;
        const totalRamGB = Math.round((flavor.ram * nodeCount) / 1024);
        const totalDiskGB = flavor.disk * nodeCount;
        
        const summaryHtml = `
            <div class="resource-summary">
                <h6><i class="fas fa-calculator"></i> Recursos Totales del Slice</h6>
                <div class="resource-item">
                    <span><i class="fas fa-microchip"></i> vCPUs:</span>
                    <strong>${totalVcpus}</strong>
                </div>
                <div class="resource-item">
                    <span><i class="fas fa-memory"></i> RAM:</span>
                    <strong>${totalRamGB} GB</strong>
                </div>
                <div class="resource-item">
                    <span><i class="fas fa-hdd"></i> Disco:</span>
                    <strong>${totalDiskGB} GB</strong>
                </div>
                <div class="resource-item">
                    <span><i class="fas fa-server"></i> VMs:</span>
                    <strong>${nodeCount}</strong>
                </div>
            </div>
        `;
        
        $('#summaryContent').html(summaryHtml);
        $('#sliceSummary').show();
    } else {
        $('#sliceSummary').hide();
    }
}

function toggleCloudInitSection() {
    const $section = $('#cloudInitSection');
    const $button = $('#toggleCloudInit');
    const $icon = $button.find('i');
    
    if ($section.is(':visible')) {
        $section.slideUp();
        $icon.removeClass('fa-chevron-up').addClass('fa-chevron-down');
        $button.html('<i class="fas fa-chevron-down"></i> Mostrar');
    } else {
        $section.slideDown();
        $icon.removeClass('fa-chevron-down').addClass('fa-chevron-up');
        $button.html('<i class="fas fa-chevron-up"></i> Ocultar');
    }
}

function showSlicePreview() {
    const formData = collectFormData();
    
    if (!validateFormData(formData)) {
        return;
    }
    
    const selectedFlavor = $('#vmFlavor option:selected').data('flavor');
    const selectedImage = $('#vmImage option:selected').data('image');
    
    const previewHtml = `
        <div class="row">
            <div class="col-md-6">
                <h6><i class="fas fa-info-circle"></i> Información General</h6>
                <table class="table table-sm">
                    <tr><td><strong>Nombre:</strong></td><td>${formData.name}</td></tr>
                    <tr><td><strong>Topología:</strong></td><td>${$('#topologyType option:selected').text()}</td></tr>
                    <tr><td><strong>Número de VMs:</strong></td><td>${formData.node_count}</td></tr>
                    <tr><td><strong>Prefijo VMs:</strong></td><td>${formData.vm_prefix || 'auto'}</td></tr>
                </table>
                
                <h6><i class="fas fa-server"></i> Configuración de VMs</h6>
                <table class="table table-sm">
                    <tr><td><strong>Flavor:</strong></td><td>${selectedFlavor.name}</td></tr>
                    <tr><td><strong>Imagen:</strong></td><td>${selectedImage.name}</td></tr>
                    <tr><td><strong>vCPUs por VM:</strong></td><td>${selectedFlavor.vcpus}</td></tr>
                    <tr><td><strong>RAM por VM:</strong></td><td>${Math.round(selectedFlavor.ram/1024)}GB</td></tr>
                </table>
            </div>
            <div class="col-md-6">
                <h6><i class="fas fa-network-wired"></i> Configuración de Red</h6>
                <table class="table table-sm">
                    <tr><td><strong>Red del Slice:</strong></td><td>${formData.network_name}</td></tr>
                    <tr><td><strong>CIDR:</strong></td><td>${formData.network_cidr}</td></tr>
                    <tr><td><strong>DHCP:</strong></td><td>${formData.enable_dhcp ? 'Habilitado' : 'Deshabilitado'}</td></tr>
                    <tr><td><strong>Red Pública:</strong></td><td>Automática</td></tr>
                </table>
                
                <h6><i class="fas fa-list"></i> VMs a Crear</h6>
                <div class="list-group">
        `;
    
    for (let i = 1; i <= formData.node_count; i++) {
        const vmName = `${formData.vm_prefix || formData.name}-${i}`;
        previewHtml += `
            <div class="list-group-item">
                <strong>${vmName}</strong><br>
                <small class="text-muted">${selectedFlavor.name} - ${selectedImage.name}</small>
            </div>
        `;
    }
    
    previewHtml += `
                </div>
            </div>
        </div>
    `;
    
    if (formData.cloud_init) {
        previewHtml += `
            <div class="mt-3">
                <h6><i class="fas fa-code"></i> Cloud-Init Script</h6>
                <pre class="bg-light p-3 border rounded">${formData.cloud_init}</pre>
            </div>
        `;
    }
    
    $('#summaryContent').html(previewHtml);
    $('#sliceSummary').show();
    
    // Scroll al resumen
    $('html, body').animate({
        scrollTop: $('#sliceSummary').offset().top - 100
    }, 500);
}

function collectFormData() {
    return {
        name: $('#sliceName').val().trim(),
        description: $('#description').val().trim(),
        topology_type: $('#topologyType').val(),
        node_count: parseInt($('#nodeCount').val()),
        vm_prefix: $('#vmNamePrefix').val().trim(),
        flavor: $('#vmFlavor').val(),
        image: $('#vmImage').val(),
        network_name: $('#sliceNetworkName').val().trim(),
        network_cidr: $('#sliceNetworkCidr').val().trim(),
        enable_dhcp: $('#enableDHCP').is(':checked'),
        cloud_init: $('#cloudInitScript').val().trim()
    };
}

function validateFormData(data) {
    if (!data.name) {
        showAlert('error', 'El nombre del slice es obligatorio');
        $('#sliceName').focus();
        return false;
    }
    
    if (!data.flavor) {
        showAlert('error', 'Debe seleccionar un flavor');
        $('#vmFlavor').focus();
        return false;
    }
    
    if (!data.image) {
        showAlert('error', 'Debe seleccionar una imagen');
        $('#vmImage').focus();
        return false;
    }
    
    if (!data.network_name) {
        showAlert('error', 'El nombre de la red del slice es obligatorio');
        $('#sliceNetworkName').focus();
        return false;
    }
    
    if (!data.network_cidr) {
        showAlert('error', 'El CIDR de la red es obligatorio');
        $('#sliceNetworkCidr').focus();
        return false;
    }
    
    // Validar formato CIDR básico
    const cidrPattern = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    if (!cidrPattern.test(data.network_cidr)) {
        showAlert('error', 'El formato del CIDR no es válido (ej: 192.168.1.0/24)');
        $('#sliceNetworkCidr').focus();
        return false;
    }
    
    if (data.node_count < 2 || data.node_count > 20) {
        showAlert('error', 'El número de VMs debe estar entre 2 y 20');
        $('#nodeCount').focus();
        return false;
    }
    
    return true;
}

function submitSlice(e) {
    e.preventDefault();
    
    const formData = collectFormData();
    
    if (!validateFormData(formData)) {
        return;
    }
    
    // Confirmar creación
    if (!confirm(`¿Está seguro de crear el slice "${formData.name}" con ${formData.node_count} VMs?\n\nEsto creará recursos reales en OpenStack.`)) {
        return;
    }
    
    console.log('Creando slice con datos:', formData);
    
    showProgressModal('Iniciando creación del slice...');
    
    $.ajax({
        url: '/slice/create',
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify(formData),
        success: function(response) {
            hideProgressModal();
            
            if (response.success) {
                showAlert('success', `Slice "${formData.name}" creado exitosamente!`);
                
                // Mostrar información del slice creado
                const infoHtml = `
                    <div class="alert alert-success">
                        <h5><i class="fas fa-check-circle"></i> Slice Creado Exitosamente</h5>
                        <p><strong>ID:</strong> ${response.slice_id}</p>
                        <p><strong>Nombre:</strong> ${formData.name}</p>
                        <p><strong>VMs:</strong> ${formData.node_count} instancias están siendo creadas</p>
                        <p><strong>Estado:</strong> Las VMs pueden tardar varios minutos en estar disponibles</p>
                    </div>
                `;
                
                $('#summaryContent').html(infoHtml);
                $('#sliceSummary').show();
                
                // Redirigir después de 3 segundos
                setTimeout(() => {
                    window.location.href = '/slices';
                }, 3000);
                
            } else {
                showAlert('error', response.error || 'Error desconocido al crear el slice');
            }
        },
        error: function(xhr) {
            hideProgressModal();
            const error = xhr.responseJSON?.error || 'Error de conexión';
            showAlert('error', 'Error al crear el slice: ' + error);
            console.error('Error creating slice:', xhr);
        }
    });
}

function showProgressModal(message) {
    $('#progressMessage').text(message);
    $('#progressModal').modal('show');
}

function hideProgressModal() {
    $('#progressModal').modal('hide');
}

function showAlert(type, message) {
    const alertClass = type === 'error' ? 'alert-danger' : 
                     type === 'success' ? 'alert-success' : 
                     type === 'info' ? 'alert-info' : 'alert-warning';
    
    const icon = type === 'error' ? 'fa-exclamation-triangle' : 
                type === 'success' ? 'fa-check-circle' : 
                type === 'info' ? 'fa-info-circle' : 'fa-exclamation-circle';
    
    const alert = $(`
        <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
            <i class="fas ${icon}"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `);
    
    // Limpiar alertas anteriores
    $('.container .alert').remove();
    
    // Agregar nueva alerta al inicio del container
    $('.container').prepend(alert);
    
    // Auto-dismiss después de 5 segundos para alertas de info y success
    if (type === 'info' || type === 'success') {
        setTimeout(() => {
            alert.alert('close');
        }, 5000);
    }
    
    // Scroll al top para mostrar la alerta
    $('html, body').animate({ scrollTop: 0 }, 300);
}