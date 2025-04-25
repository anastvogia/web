// public/main.js

// Inject data into the index page (thesis list)
window.addEventListener('DOMContentLoaded', () => {
    const path = window.location.pathname;
  
    // If we're on the index page
    if (path === '/secretariat-home.html') {
        fetch('/api/thesis')
          .then(res => res.json())
          .then(thesis => {
            const tbody = document.getElementById('thesis-body');
            tbody.innerHTML = '';
      
            thesis.forEach(thesis => {
              // Check if the status is either "Active" or "Under Review"
              if (thesis.status === "active" || thesis.status === "under_review") {
                const row = document.createElement('tr');
                row.innerHTML = `
                  <td><a href="thesis.html?id=${thesis.id}">${thesis.title}</a></td>
                  <td>${thesis.status}</td>
                  <td>${thesis.assigned_date.slice(0, -14)}</td>
                `;
                tbody.appendChild(row);
              }
            });
          })
          .catch(err => {
            console.error('Failed to load thesis:', err);
          });
      }
      
  
    // If we're on the thesis detail page

    if (path === '/thesis.html') {
      const thesisId = new URLSearchParams(window.location.search).get('id');
      if (thesisId) {
        fetch(`/api/thesis/${thesisId}`)
          .then(res => res.json())
          .then(entry => {
            document.getElementById('thesis-title').textContent = entry.title;
            document.getElementById('thesis-status').textContent = entry.status;
            document.getElementById('thesis-assigned-date').textContent = entry.assigned_date.slice(0, -14);
            document.getElementById('thesis-description').textContent = entry.description;
            document.getElementById('thesis-committee').textContent = entry.committee_names || 'pending';
          })
          .catch(err => {
            console.error('Failed to load thesis:', err);
          });
      }
    }
    
    if (path === '/student-home.html') {
      fetch('/api/student-thesis')
        .then(res => {
          if (!res.ok) {
            throw new Error('Failed to fetch student thesis');
          }
          return res.json();
        })
        .then(thesis => {
          document.getElementById('thesis-title').textContent = thesis.title || 'N/A';
          document.getElementById('thesis-status').textContent = thesis.status || 'N/A';
          document.getElementById('thesis-assigned-date').textContent = thesis.assigned_date
            ? thesis.assigned_date.slice(0, -14)
            : 'N/A';
          document.getElementById('thesis-description').textContent = thesis.description || 'N/A';
          document.getElementById('thesis-committee').textContent = thesis.committee || 'N/A';
    
          // Time elapsed (optional)
          if (thesis.assigned_date) {
            const assignedDate = new Date(thesis.assigned_date);
            const now = new Date();
            const months = Math.floor((now - assignedDate) / (1000 * 60 * 60 * 24 * 30));
            document.getElementById('thesis-elapsed').textContent = `${months} month${months !== 1 ? 's' : ''}`;
          } else {
            document.getElementById('thesis-elapsed').textContent = 'N/A';
          }
    
          // Download file URL
          const downloadLink = document.getElementById('thesis-download');
          if (thesis.id) {
            downloadLink.href = `/thesis/thesis-description-${thesis.id}.pdf`;
            downloadLink.style.display = 'inline-block';
          } else {
            downloadLink.style.display = 'none';
          }
        })
        .catch(err => {
          console.error('Failed to load student thesis:', err);
        });
    }    

    document.getElementById('protocol-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
    
      const thesisId = document.getElementById('thesis_id').value;
      const protocolNumber = document.getElementById('protocol_number').value;
      const assemblyDate = document.getElementById('assembly_date').value;
    
      try {
        const res = await fetch('/api/register-protocol', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ thesisId, protocolNumber, assemblyDate })
        });
    
        const result = await res.json();
        alert(result.success ? 'Protocol registered successfully!' : 'Failed to register protocol.');
      } catch (err) {
        console.error('Error registering protocol:', err);
        alert('An error occurred while registering the protocol.');
      }
    });




  });
