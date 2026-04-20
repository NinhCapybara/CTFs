document.getElementById('ipForm').addEventListener('submit', function(e) {
    e.preventDefault();
    const ip = document.getElementById('ipInput').value;
    fetch(`http://ip-api.com/json/${ip}`)
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = `
                <p><strong>IP:</strong> ${data.query}</p>
                <p><strong>Country:</strong> ${data.country}</p>
                <p><strong>Region:</strong> ${data.regionName}</p>
                <p><strong>City:</strong> ${data.city}</p>
                <p><strong>Latitude:</strong> ${data.lat}</p>
                <p><strong>Longitude:</strong> ${data.lon}</p>
            `;
        })
        .catch(error => {
            document.getElementById('result').innerHTML = '<p>Unable to recover data. Try again.</p>';
        });
});
