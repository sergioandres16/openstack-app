// PUCP Cloud Orchestrator - Main JavaScript Application

$(document).ready(function() {
    // Initialize application
    initializeApp();
    
    // Setup global event handlers
    setupGlobalHandlers();
    
    // Auto-refresh data
    setupAutoRefresh();
});

function initializeApp() {
    console.log('🚀 PUCP Cloud Orchestrator initialized');
    
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Setup CSRF token for AJAX requests
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
            }
        }
    });
}

function setupGlobalHandlers() {
    // Global error handler for AJAX requests
    $(document).ajaxError(function(event, xhr, settings, thrownError) {
        if (xhr.status === 401) {
            showAlert('error', 'Sesión expirada. Redirigiendo al login...');
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else if (xhr.status === 403) {
            showAlert('error', 'No tienes permisos para realizar esta acción');
        } else if (xhr.status >= 500) {
            showAlert('error', 'Error del servidor. Por favor intenta nuevamente');
        }
    });
    
    // Auto-dismiss alerts
    $(document).on('click', '.alert .btn-close', function() {
        $(this).closest('.alert').fadeOut();
    });
    
    // Confirm dangerous actions
    $(document).on('click', '[data-confirm]', function(e) {
        const message = $(this).data('confirm');
        if (!confirm(message)) {
            e.preventDefault();
            return false;
        }
    });
    
    // Copy to clipboard functionality
    $(document).on('click', '[data-copy]', function() {
        const text = $(this).data('copy');
        navigator.clipboard.writeText(text).then(() => {
            showAlert('success', 'Copiado al portapapeles');
        });
    });
}

function setupAutoRefresh() {
    // Auto-refresh dashboard every 30 seconds
    if (window.location.pathname === '/dashboard') {
        setInterval(refreshDashboardData, 30000);
    }
    
    // Auto-refresh slices list every 60 seconds
    if (window.location.pathname === '/slices') {
        setInterval(refreshSlicesList, 60000);
    }
}

function refreshDashboardData() {
    // Refresh resource data without full page reload
    $.get('/api/resources/status')
        .done(function(data) {
            updateResourceDisplays(data);
        })
        .fail(function() {
            console.log('Failed to refresh dashboard data');
        });
}

function refreshSlicesList() {
    // Refresh slice statuses
    $('.slice-card').each(function() {
        const sliceId = $(this).data('slice-id');
        if (sliceId) {
            refreshSliceStatus(sliceId, $(this));
        }
    });
}

function refreshSliceStatus(sliceId, cardElement) {
    $.get(`/api/slices/${sliceId}/status`)
        .done(function(data) {
            const statusBadge = cardElement.find('.badge');
            const currentStatus = statusBadge.text().toLowerCase();
            const newStatus = data.status.toLowerCase();
            
            if (currentStatus !== newStatus) {
                statusBadge.removeClass('bg-success bg-warning bg-danger bg-secondary');
                statusBadge.addClass(getStatusClass(newStatus));
                statusBadge.text(data.status);
                
                // Show notification for status change
                showAlert('info', `Slice "${data.name}" cambió a estado: ${data.status}`);
            }
        })
        .fail(function() {
            console.log(`Failed to refresh status for slice ${sliceId}`);
        });
}

function getStatusClass(status) {
    const statusClasses = {
        'active': 'bg-success',
        'deploying': 'bg-warning',
        'error': 'bg-danger',
        'draft': 'bg-secondary'
    };
    return statusClasses[status] || 'bg-secondary';
}

function updateResourceDisplays(data) {
    // Update progress bars and metrics
    if (data.linux) {
        updateProgressBar('#linux-cpu-progress', data.linux.cpu_usage);
        updateProgressBar('#linux-ram-progress', data.linux.ram_usage);
        updateProgressBar('#linux-disk-progress', data.linux.disk_usage);
    }
    
    if (data.openstack) {
        updateProgressBar('#openstack-instances-progress', data.openstack.instances_usage);
        updateProgressBar('#openstack-vcpus-progress', data.openstack.vcpus_usage);
        updateProgressBar('#openstack-ram-progress', data.openstack.ram_usage);
    }
}

function updateProgressBar(selector, percentage) {
    const progressBar = $(selector);
    if (progressBar.length) {
        progressBar.css('width', percentage + '%');
        progressBar.attr('aria-valuenow', percentage);
    }
}

// Global utility functions
function showAlert(type, message, duration = 5000) {
    const alertTypes = {
        'success': 'alert-success',
        'error': 'alert-danger',
        'warning': 'alert-warning',
        'info': 'alert-info'
    };
    
    const icons = {
        'success': 'fa-check-circle',
        'error': 'fa-exclamation-triangle',
        'warning': 'fa-exclamation-circle',
        'info': 'fa-info-circle'
    };
    
    const alertClass = alertTypes[type] || 'alert-info';
    const icon = icons[type] || 'fa-info-circle';
    
    const alertId = 'alert-' + Date.now();
    const alertHtml = `
        <div id="${alertId}" class="alert ${alertClass} alert-dismissible fade show" role="alert">
            <i class="fas ${icon}"></i> ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    // Add to page
    if ($('.container-fluid').length) {
        $('.container-fluid').prepend(alertHtml);
    } else if ($('.container').length) {
        $('.container').prepend(alertHtml);
    } else {
        $('body').prepend('<div class="container">' + alertHtml + '</div>');
    }
    
    // Auto-dismiss
    if (duration > 0) {
        setTimeout(() => {
            $(`#${alertId}`).fadeOut(500, function() {
                $(this).remove();
            });
        }, duration);
    }
}

function showSpinner(message = 'Cargando...') {
    const spinnerId = 'global-spinner-' + Date.now();
    const spinnerHtml = `
        <div id="${spinnerId}" class="modal fade" tabindex="-1" data-bs-backdrop="static">
            <div class="modal-dialog modal-sm">
                <div class="modal-content">
                    <div class="modal-body text-center py-4">
                        <div class="spinner-border text-primary mb-3" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <p class="mb-0">${message}</p>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    $('body').append(spinnerHtml);
    $(`#${spinnerId}`).modal('show');
    
    return spinnerId;
}

function hideSpinner(spinnerId) {
    if (spinnerId) {
        $(`#${spinnerId}`).modal('hide');
        setTimeout(() => {
            $(`#${spinnerId}`).remove();
        }, 300);
    }
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('es-ES', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function validateIPAddress(ip) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
}

function validateCIDR(cidr) {
    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
    return cidrRegex.test(cidr);
}

// Keyboard shortcuts
$(document).keydown(function(e) {
    // Ctrl+Shift+N: New slice
    if (e.ctrlKey && e.shiftKey && e.keyCode === 78) {
        e.preventDefault();
        window.location.href = '/slice/create';
    }
    
    // Ctrl+Shift+D: Dashboard
    if (e.ctrlKey && e.shiftKey && e.keyCode === 68) {
        e.preventDefault();
        window.location.href = '/dashboard';
    }
    
    // Ctrl+Shift+S: Slices list
    if (e.ctrlKey && e.shiftKey && e.keyCode === 83) {
        e.preventDefault();
        window.location.href = '/slices';
    }
});

// Console integration
function openConsole(vmId, vmName) {
    const consoleWindow = window.open(
        `/console/${vmId}`,
        `console-${vmId}`,
        'width=800,height=600,scrollbars=yes,resizable=yes'
    );
    
    if (consoleWindow) {
        consoleWindow.focus();
        showAlert('info', `Abriendo consola para ${vmName}`);
    } else {
        showAlert('error', 'No se pudo abrir la consola. Verifica que no esté bloqueada por el navegador.');
    }
}

// Export functions for global use
window.PUCP = {
    showAlert,
    showSpinner,
    hideSpinner,
    formatBytes,
    formatDate,
    validateIPAddress,
    validateCIDR,
    openConsole
};