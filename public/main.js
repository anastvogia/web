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
              if (thesis.status === "Active" || thesis.status === "Under Review") {
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
            document.getElementById('thesis-committee').textContent = entry.committee;
          })
          .catch(err => {
            console.error('Failed to load thesis:', err);
          });
      }
    }
    
    // if (path === '/thesis.html') {
    //   const thesisId = new URLSearchParams(window.location.search).get('id');
    //   if (thesisId) {
    //     fetch(`/api/thesis`)
    //       .then(res => res.json())
    //       .then(thesis => {
    //         const entry = thesis.find(t => t.id == thesisId);
    //         if (thesis) {
    //             console.log(thesisId.title);
    //           // Inject thesis data into the page
    //           document.getElementById('thesis-title').textContent = entry.title;
    //           document.getElementById('thesis-status').textContent = entry.status;
    //           document.getElementById('thesis-assigned-date').textContent = entry.assigned_date.slice(0, -14);
    //           document.getElementById('thesis-description').textContent = entry.description;
    //           document.getElementById('thesis-committee').textContent = entry.committee;
    //         } else {
    //           console.error('Thesis not found');
    //         }
    //       })
    //       .catch(err => {
    //         console.error('Failed to load thesis:', err);
    //       });
    //   }
    // }
  });
  