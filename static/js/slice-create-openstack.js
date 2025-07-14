// PUCP Cloud Orchestrator - Slice Creation for OpenStack (Simplified)

$(document).ready(function() {
    console.log('🚀 Slice Creator iniciado');
    
    // Verificar jQuery
    if (typeof $ === 'undefined') {
        console.error('❌ jQuery no disponible');
        return;
    }
    
    // TEST 1: Verificar elementos DOM
    testDOMElements();
    
    // TEST 2: Poblar directamente
    testDirectPopulate();
    
    // TEST 3: Llamadas AJAX después de 2 segundos
    setTimeout(testAJAXCalls, 2000);
    
    // Event listeners
    setupEventListeners();
});

function testDOMElements() {
    console.log('===== TEST 1: DOM ELEMENTS =====');
    
    const elements = {
        'vmFlavor': $('#vmFlavor'),
        'vmImage': $('#vmImage'), 
        'toggleCloudInit': $('#toggleCloudInit')
    };
    
    for (const [name, element] of Object.entries(elements)) {
        console.log(`${name}:`, element.length > 0 ? '✅ Found' : '❌ Missing');
    }
}

function testDirectPopulate() {
    console.log('===== TEST 2: DIRECT POPULATE =====');
    
    const flavorSelect = $('#vmFlavor');
    const imageSelect = $('#vmImage');
    
    if (flavorSelect.length === 0 || imageSelect.length === 0) {
        console.error('❌ Elementos select no encontrados');
        return;
    }
    
    // Poblar flavors
    flavorSelect.empty();
    flavorSelect.append('<option value="">Seleccione un flavor...</option>');
    flavorSelect.append('<option value="m1.tiny">m1.tiny - 1 vCPU, 512MB RAM, 1GB Disk</option>');
    flavorSelect.append('<option value="m1.small">m1.small - 1 vCPU, 2GB RAM, 20GB Disk</option>');
    flavorSelect.append('<option value="m1.medium">m1.medium - 2 vCPU, 4GB RAM, 40GB Disk</option>');
    
    // Poblar imágenes
    imageSelect.empty();
    imageSelect.append('<option value="">Seleccione una imagen...</option>');
    imageSelect.append('<option value="ubuntu-20.04">Ubuntu 20.04 LTS (2GB)</option>');
    imageSelect.append('<option value="ubuntu-22.04">Ubuntu 22.04 LTS (2GB)</option>');
    imageSelect.append('<option value="centos-8">CentOS 8 Stream (2GB)</option>');
    
    console.log('✅ Populate directo completado');
    console.log(`Flavors: ${flavorSelect.find('option').length} opciones`);
    console.log(`Images: ${imageSelect.find('option').length} opciones`);
}

function testAJAXCalls() {
    console.log('===== TEST 3: AJAX CALLS =====');
    
    // Test simple endpoint
    $.ajax({
        url: '/api/test',
        method: 'GET',
        timeout: 5000,
        success: function(response) {
            console.log('✅ /api/test OK:', response);
            testFlavorEndpoint();
        },
        error: function(xhr, status, error) {
            console.error('❌ /api/test FAIL:', status, error);
            testFlavorEndpoint(); // Continuar de todas formas
        }
    });
}

function testFlavorEndpoint() {
    console.log('Testing /api/openstack/flavors...');
    
    $.ajax({
        url: '/api/openstack/flavors',
        method: 'GET',
        timeout: 5000,
        success: function(response) {
            console.log('✅ Flavors endpoint OK:', response);
            
            if (response && response.success && response.flavors && response.flavors.length > 0) {
                console.log(`📋 ${response.flavors.length} flavors recibidos`);
                populateFlavorSelect(response.flavors);
            } else {
                console.warn('⚠️ Respuesta de flavors inválida');
            }
            
            testImageEndpoint();
        },
        error: function(xhr, status, error) {
            console.error('❌ Flavors endpoint FAIL:', status, error);
            console.error('Response:', xhr.responseText);
            testImageEndpoint();
        }
    });
}

function testImageEndpoint() {
    console.log('Testing /api/openstack/images...');
    
    $.ajax({
        url: '/api/openstack/images',
        method: 'GET',
        timeout: 5000,
        success: function(response) {
            console.log('✅ Images endpoint OK:', response);
            
            if (response && response.success && response.images && response.images.length > 0) {
                console.log(`📋 ${response.images.length} images recibidas`);
                populateImageSelect(response.images);
            } else {
                console.warn('⚠️ Respuesta de images inválida');
            }
        },
        error: function(xhr, status, error) {
            console.error('❌ Images endpoint FAIL:', status, error);
            console.error('Response:', xhr.responseText);
        }
    });
}

function populateFlavorSelect(flavors) {
    console.log('Populando flavor select con datos reales...');
    
    const flavorSelect = $('#vmFlavor');
    flavorSelect.empty();
    flavorSelect.append('<option value="">Seleccione un flavor...</option>');
    
    flavors.forEach(flavor => {
        const ramGB = Math.round(flavor.ram / 1024);
        const option = `<option value="${flavor.id}">${flavor.name} - ${flavor.vcpus} vCPUs, ${ramGB}GB RAM, ${flavor.disk}GB Disk</option>`;
        flavorSelect.append(option);
    });
    
    console.log(`✅ ${flavors.length} flavors poblados`);
}

function populateImageSelect(images) {
    console.log('Populando image select con datos reales...');
    
    const imageSelect = $('#vmImage');
    imageSelect.empty();
    imageSelect.append('<option value="">Seleccione una imagen...</option>');
    
    images.forEach(image => {
        const sizeGB = image.size ? Math.round(image.size / (1024 * 1024 * 1024)) : 'N/A';
        const option = `<option value="${image.id}">${image.name} (${sizeGB}GB)</option>`;
        imageSelect.append(option);
    });
    
    console.log(`✅ ${images.length} images pobladas`);
}

function setupEventListeners() {
    console.log('Configurando event listeners...');
    
    // Cloud-Init toggle
    $('#toggleCloudInit').off('click').on('click', function(e) {
        e.preventDefault();
        console.log('Cloud-Init toggle clicked');
        
        const section = $('#cloudInitSection');
        const button = $(this);
        const icon = button.find('i');
        
        if (section.is(':visible')) {
            section.slideUp();
            icon.removeClass('fa-chevron-up').addClass('fa-chevron-down');
            button.html('<i class="fas fa-chevron-down"></i> Mostrar');
        } else {
            section.slideDown();
            icon.removeClass('fa-chevron-down').addClass('fa-chevron-up');
            button.html('<i class="fas fa-chevron-up"></i> Ocultar');
        }
    });
    
    // Flavor change
    $('#vmFlavor').off('change').on('change', function() {
        const selected = $(this).find(':selected');
        const text = selected.text();
        $('#flavorDetails').text(text || 'Seleccione un flavor para ver detalles');
    });
    
    // Image change  
    $('#vmImage').off('change').on('change', function() {
        const selected = $(this).find(':selected');
        const text = selected.text();
        $('#imageDetails').text(text || 'Seleccione una imagen para ver detalles');
    });
    
    console.log('✅ Event listeners configurados');
}

function showSimpleAlert(type, message) {
    if (window.PUCP && typeof window.PUCP.showAlert === 'function') {
        window.PUCP.showAlert(type, message);
    } else {
        console.log(`[${type.toUpperCase()}] ${message}`);
    }
}