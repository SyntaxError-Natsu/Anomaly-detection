// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl, {
            container: 'body',
            html: true
        });
    });
    
    // Toggle sidebar
    document.getElementById('sidebarCollapse').addEventListener('click', function() {
        document.getElementById('sidebar').classList.toggle('active');
        document.getElementById('content').classList.toggle('active');
    });
    
    // Example presets for prediction form
    const normalExampleBtn = document.getElementById('normalExample');
    if (normalExampleBtn) {
        normalExampleBtn.addEventListener('click', function() {
            // Set values for normal HTTP traffic
            document.getElementById('duration').value = '0';
            document.getElementById('protocoltype').value = 'tcp';
            document.getElementById('service').value = 'http';
            document.getElementById('flag').value = 'SF';
            document.getElementById('srcbytes').value = '215';
            document.getElementById('dstbytes').value = '45076';
            document.getElementById('count').value = '1';
            document.getElementById('serrorrate').value = '0';
            document.getElementById('rerrorrate').value = '0';
            document.getElementById('samesrvrate').value = '1';
            // Set other fields as needed
        });
    }
    
    const dosExampleBtn = document.getElementById('dosExample');
    if (dosExampleBtn) {
        dosExampleBtn.addEventListener('click', function() {
            // Set values for DoS attack (Neptune)
            document.getElementById('duration').value = '0';
            document.getElementById('protocoltype').value = 'tcp';
            document.getElementById('service').value = 'private';
            document.getElementById('flag').value = 'S0';
            document.getElementById('srcbytes').value = '0';
            document.getElementById('dstbytes').value = '0';
            document.getElementById('count').value = '123';
            document.getElementById('serrorrate').value = '1';
            document.getElementById('rerrorrate').value = '0';
            document.getElementById('samesrvrate').value = '0';
            // Set other fields as needed
        });
    }
    
    const probeExampleBtn = document.getElementById('probeExample');
    if (probeExampleBtn) {
        probeExampleBtn.addEventListener('click', function() {
            // Set values for Probe attack
            document.getElementById('duration').value = '0';
            document.getElementById('protocoltype').value = 'icmp';
            document.getElementById('service').value = 'eco_i';
            document.getElementById('flag').value = 'SF';
            document.getElementById('srcbytes').value = '20';
            document.getElementById('dstbytes').value = '0';
            document.getElementById('count').value = '1';
            document.getElementById('serrorrate').value = '0';
            document.getElementById('rerrorrate').value = '0';
            document.getElementById('samesrvrate').value = '1';
            // Set other fields as needed
        });
    }
    
    const r2lExampleBtn = document.getElementById('r2lExample');
    if (r2lExampleBtn) {
        r2lExampleBtn.addEventListener('click', function() {
            // Set values for R2L attack (guess_passwd)
            document.getElementById('duration').value = '0';
            document.getElementById('protocoltype').value = 'tcp';
            document.getElementById('service').value = 'telnet';
            document.getElementById('flag').value = 'SF';
            document.getElementById('srcbytes').value = '129';
            document.getElementById('dstbytes').value = '174';
            document.getElementById('count').value = '1';
            document.getElementById('serrorrate').value = '0';
            document.getElementById('rerrorrate').value = '0';
            document.getElementById('samesrvrate').value = '1';
            // Set other fields as needed
        });
    }
    
    // Reset form
    const resetFormBtn = document.getElementById('resetForm');
    if (resetFormBtn) {
        resetFormBtn.addEventListener('click', function() {
            document.getElementById('predictionForm').reset();
        });
    }
    
    // Close results
    const closeResultsBtn = document.getElementById('closeResults');
    if (closeResultsBtn) {
        closeResultsBtn.addEventListener('click', function() {
            document.getElementById('resultSection').style.display = 'none';
        });
    }
    
    // Initialize charts if they exist on the page
    initializeCharts();
});

// Function to initialize charts
function initializeCharts() {
    // Attack Timeline Chart
    const attackTimelineChart = document.getElementById('attackTimelineChart');
    if (attackTimelineChart) {
        const ctx = attackTimelineChart.getContext('2d');
        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: timelineLabels,
                datasets: [
                    {
                        label: 'DoS Attacks',
                        data: dosTimeline,
                        borderColor: '#4e73df',
                        backgroundColor: 'rgba(78, 115, 223, 0.1)',
        tension: 0.3,
        fill: true
      },
      {
        label: 'Probe Attacks',
        data: probeTimeline,
        borderColor: '#1cc88a',
        backgroundColor: 'rgba(28, 200, 138, 0.1)',
        tension: 0.3,
        fill: true
      },
      {
        label: 'R2L Attacks',
        data: r2lTimeline,
        borderColor: '#36b9cc',
        backgroundColor: 'rgba(54, 185, 204, 0.1)',
        tension: 0.3,
        fill: true
      },
      {
        label: 'U2R Attacks',
        data: u2rTimeline,
        borderColor: '#f6c23e',
        backgroundColor: 'rgba(246, 194, 62, 0.1)',
        tension: 0.3,
        fill: true
      }
    ]
  },
  options: {
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: 'top'
      },
      tooltip: {
        mode: 'index',
        intersect: false
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        title: {
          display: true,
          text: 'Number of Attacks'
        }
      },
      x: {
        title: {
          display: true,
          text: 'Time'
        }
      }
    }
  }
});

// Event listeners for timeline dropdown
document.getElementById('daily').addEventListener('click', function() {
  updateTimelineChart('daily');
});
document.getElementById('weekly').addEventListener('click', function() {
  updateTimelineChart('weekly');
});
document.getElementById('monthly').addEventListener('click', function() {
  updateTimelineChart('monthly');
});
}

// Initialize Plotly charts if they exist
const attackDistributionChart = document.getElementById('attackDistributionChart');
if (attackDistributionChart && typeof attackDistribution !== 'undefined') {
  Plotly.newPlot('attackDistributionChart', [{
    values: [
      attackDistribution.dos,
      attackDistribution.probe,
      attackDistribution.r2l,
      attackDistribution.u2r,
      attackDistribution.normal
    ],
    labels: ['DoS', 'Probe', 'R2L', 'U2R', 'Normal'],
    type: 'pie',
    hole: 0.4,
    marker: {
      colors: ['#4e73df', '#1cc88a', '#36b9cc', '#f6c23e', '#858796']
    }
  }], {
    title: 'Attack Type Distribution',
    height: 340,
    margin: {l: 30, r: 30, t: 40, b: 30}
  });
}

const protocolDistributionChart = document.getElementById('protocolDistributionChart');
if (protocolDistributionChart && typeof protocolNormal !== 'undefined') {
  Plotly.newPlot('protocolDistributionChart', [
    {
      x: ['TCP', 'UDP', 'ICMP'],
      y: protocolNormal,
      name: 'Normal Traffic',
      type: 'bar',
      marker: {color: '#1cc88a'}
    },
    {
      x: ['TCP', 'UDP', 'ICMP'],
      y: protocolAnomalous,
      name: 'Anomalous Traffic',
      type: 'bar',
      marker: {color: '#e74a3b'}
    }
  ], {
    barmode: 'group',
    title: 'Protocol Distribution',
    height: 340,
    margin: {l: 40, r: 30, t: 40, b: 40},
    xaxis: {title: 'Protocol Type'},
    yaxis: {title: 'Count'}
  });
}

const featureImportanceChart = document.getElementById('featureImportanceChart');
if (featureImportanceChart && typeof visualizations !== 'undefined' && visualizations.feature_importance) {
  const featureImportanceData = JSON.parse(visualizations.feature_importance);
  Plotly.newPlot('featureImportanceChart', featureImportanceData.data, featureImportanceData.layout);
}

const correlationHeatmapChart = document.getElementById('correlationHeatmapChart');
if (correlationHeatmapChart && typeof visualizations !== 'undefined' && visualizations.correlation_heatmap) {
  const correlationData = JSON.parse(visualizations.correlation_heatmap);
  Plotly.newPlot('correlationHeatmapChart', correlationData.data, correlationData.layout);
}

// Function to update timeline chart
function updateTimelineChart(timeframe) {
  fetch(`/api/timeline-data?timeframe=${timeframe}`)
    .then(response => response.json())
    .then(data => {
      const chart = Chart.getChart(document.getElementById('attackTimelineChart'));
      if (chart) {
        chart.data.labels = data.labels;
        chart.data.datasets[0].data = data.dos;
        chart.data.datasets[1].data = data.probe;
        chart.data.datasets[2].data = data.r2l;
        chart.data.datasets[3].data = data.u2r;
        chart.update();
      }
    })
    .catch(error => console.error('Error fetching timeline data:', error));
}

// Handle prediction form submission
const predictionForm = document.getElementById('predictionForm');
if (predictionForm) {
  predictionForm.addEventListener('submit', function(e) {
    e.preventDefault();
    
    // Show loading indicator
    const submitBtn = this.querySelector('button[type="submit"]');
    const originalBtnText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Analyzing...';
    submitBtn.disabled = true;
    
    // Submit form normally (page will be redirected to results)
    this.submit();
  });
}

// Feature explanation tooltips
const featureInfoButtons = document.querySelectorAll('.feature-info-btn');
if (featureInfoButtons.length > 0) {
  featureInfoButtons.forEach(button => {
    button.addEventListener('click', function() {
      const featureName = this.getAttribute('data-feature');
      fetch(`/api/feature-explanation?feature=${featureName}`)
        .then(response => response.json())
        .then(data => {
          const modalTitle = document.getElementById('featureModalLabel');
          const modalBody = document.getElementById('featureModalBody');
          
          modalTitle.textContent = `Feature: ${featureName}`;
          modalBody.innerHTML = `
            <p>${data.explanation}</p>
            <div class="mt-3">
              <strong>Importance Score:</strong>
              <div class="progress">
                <div class="progress-bar" role="progressbar" style="width: ${data.importance * 100}%;" 
                  aria-valuenow="${data.importance * 100}" aria-valuemin="0" aria-valuemax="100">
                  ${(data.importance * 100).toFixed(1)}%
                </div>
              </div>
            </div>
          `;
          
          const featureModal = new bootstrap.Modal(document.getElementById('featureModal'));
          featureModal.show();
        })
        .catch(error => console.error('Error fetching feature explanation:', error));
    });
  });
}

// Real-time monitoring simulation
function updateMonitoringData() {
  const monitoringSection = document.getElementById('monitoringSection');
  if (monitoringSection) {
    fetch('/api/monitoring-data')
      .then(response => response.json())
      .then(data => {
        document.getElementById('currentTime').textContent = data.time;
        document.getElementById('normalCount').textContent = data.traffic.normal;
        document.getElementById('suspiciousCount').textContent = data.traffic.suspicious;
        document.getElementById('attackCount').textContent = data.traffic.attack;
        
        // Update protocol distribution
        document.getElementById('tcpCount').textContent = data.protocols.tcp;
        document.getElementById('udpCount').textContent = data.protocols.udp;
        document.getElementById('icmpCount').textContent = data.protocols.icmp;
      })
      .catch(error => console.error('Error fetching monitoring data:', error));
  }
}

// Update monitoring data every 5 seconds if monitoring section exists
if (document.getElementById('monitoringSection')) {
  updateMonitoringData();
  setInterval(updateMonitoringData, 5000);
}
}
