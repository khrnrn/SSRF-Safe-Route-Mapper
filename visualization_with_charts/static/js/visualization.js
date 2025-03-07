document.addEventListener("DOMContentLoaded", function() {
    // Stores scan summaries for scanned nodes
    let scanDetails = {};

    const svg = d3.select("svg"),
          width = +svg.attr("width"),
          height = +svg.attr("height");

    const tooltip = d3.select("body").append("div")
        .attr("id", "tooltip")
        .style("position", "absolute")
        .style("background", "white")
        .style("padding", "8px")
        .style("border-radius", "5px")
        .style("display", "none");

    const descriptionBox = document.getElementById("description");
    const scanButton = document.getElementById("scan-btn");
    const urlInput = document.getElementById("url-input");

    // Add scanning indicator
    const loadingMessage = document.createElement("p");
    loadingMessage.id = "loading-message";
    loadingMessage.style.display = "none";
    loadingMessage.style.color = "blue";
    loadingMessage.style.fontWeight = "bold";
    loadingMessage.innerText = "Scanning in progress...";
    document.getElementById("search-container").appendChild(loadingMessage);

    // Define colors based on risk level
    const riskColors = {
        "low": "blue",
        "medium": "yellow",
        "high": "red"
    };

    // Define initial graph nodes representing key components
    let nodes = [
        { id: "User", group: 1, risk: "low", description: "End user making a request." },
        { id: "Web Server", group: 2, risk: "medium", description: "Processes user requests." },
        { id: "Internal API", group: 3, risk: "high", description: "Sensitive internal API." },
        { id: "Metadata Service", group: 3, risk: "high", description: "Cloud metadata service (Common SSRF Target)." }
    ];

    // Define links representing interactions between components
    let links = [
        { source: "User", target: "Web Server", type: "User Request" },
        { source: "Web Server", target: "Internal API", type: "API Call" },
        { source: "Web Server", target: "Metadata Service", type: "Metadata Access" }
    ];

    // Initialize the force-directed graph simulation
    const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(200))
        .force("charge", d3.forceManyBody().strength(-500))
        .force("collide", d3.forceCollide(60))
        .force("center", d3.forceCenter(width / 2, height / 2));

    function renderGraph() {
        console.log("Initial nodes:", nodes);
        console.log("Initial links:", links);

        svg.selectAll("*").remove();

        // Define arrow markers for the links
        svg.append("defs").append("marker")
            .attr("id", "arrow")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 20)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-5L10,0L0,5")
            .attr("fill", "#999");

        // Create links with arrows
        const link = svg.selectAll(".link")
            .data(links)
            .enter().append("line")
            .attr("class", "link")
            .style("stroke", "#999")
            .style("stroke-width", "2px")
            .attr("marker-end", "url(#arrow)");

        // Add link labels
        const linkLabels = svg.selectAll(".link-label")
            .data(links)
            .enter().append("text")
            .attr("class", "link-label")
            .attr("text-anchor", "middle")
            .attr("dy", -5)
            .text(d => d.type)
            .style("font-size", "12px")
            .style("fill", "#666");

        // Create nodes with circles
        const node = svg.selectAll(".node")
            .data(nodes)
            .enter().append("circle")
            .attr("class", "node")
            .attr("r", 15) // Circle radius
            .style("fill", d => riskColors[d.risk])
            .style("cursor", "pointer")
            .call(d3.drag()
                .on("start", dragStarted)
                .on("drag", dragged)
                .on("end", dragEnded))
            .on("mouseover", (event, d) => {
                tooltip.style("display", "block")
                    .html(`<strong>${d.id}</strong><br>Risk: ${d.risk}`)
                    .style("left", `${event.pageX + 10}px`)
                    .style("top", `${event.pageY + 10}px`);
            })
            .on("mouseout", () => {
                tooltip.style("display", "none");
            })
            .on("click", (event, d) => {
                console.log("Node clicked:", d.id);
                console.log("Scan details available?", scanDetails[d.id] ? "Yes" : "No");

                if (scanDetails[d.id]) {
                    console.log("Displaying scan summary for:", d.id);

                    descriptionBox.innerHTML = `
                        <h4>Scan Summary</h4>
                        <p><strong>Target:</strong> ${scanDetails[d.id].target}</p>
                        <p><strong>Domain:</strong> ${scanDetails[d.id].domain}</p>
                        <p><strong>Total URLs Scanned:</strong> ${scanDetails[d.id].totalUrls}</p>
                        <p><strong>Confirmed SSRF Vulnerabilites:</strong> ${scanDetails[d.id].confirmedSSRFVulnerabilities}</p>
                        <p><strong>Potential SSRF Endpoints:</strong> ${scanDetails[d.id].potentialSSRFEndpoints}</p>
                    `;
                    
                    // NEW --------------------------------------------------------------------------------------------------------------------------------------
            
                    document.getElementById("attack-type-chart").style.display = "block";
                    document.getElementById("severity-chart").style.display = "block";

                    // Update charts using scan results
                    updatePieChart(data.scan_summary.attack_type_distribution);
                    updateBarChart(data.scan_summary.severity_distribution);
                    
                    // ------------------------------------------------------------------------------------------------------------------------------------------

                } else {
                    console.log("Displaying default details for:", d.id);
                    console.log("Node description:", d.description);
                    console.log("Node risk level:", d.risk);
                    
                    descriptionBox.innerHTML = `
                        <h4>${d.id}</h4>
                        <p><strong>Description:</strong> ${d.description}</p>
                        <p><strong>Risk Level:</strong> ${d.risk}</p>
                        <p><strong>Potential Attack Vectors:</strong> 
                            ${d.risk === "high" ? "Potential unauthorized access to internal services, metadata exposure, or SSRF exploitation." :
                            d.risk === "medium" ? "Possible exposure to user-supplied data, may require additional validation." :
                            "Minimal risk"}
                        </p>
                        <p><strong>Mitigation Strategies:</strong> 
                            ${d.risk === "high" ? "1. Implement strict allow-listing for external requests.<br>2. Block access to internal metadata services.<br>3. Use proper input validation and restrict non-essential protocols." :
                            d.risk === "medium" ? "1. Validate and sanitize user inputs.<br>2. Restrict request forwarding.<br>3. Implement least privilege access control." :
                            "Standard security best practices apply."}
                        </p>
                    `;

                    // NEW -------------------------------------------------------------------------------------------------------------------------------------------
                    
                    document.getElementById("attack-type-chart").style.display = "none";
                    document.getElementById("severity-chart").style.display = "none";
                    
                    // -----------------------------------------------------------------------------------------------------------------------------------------------
                }
            });

        // Add node labels
        const labels = svg.selectAll(".label")
            .data(nodes)
            .enter().append("text")
            .attr("class", "label")
            .attr("text-anchor", "middle")
            .attr("dy", 30)
            .text(d => d.id.length > 40 ? d.id.substring(0, 37) + "..." : d.id) // Truncate long URLs
            .style("font-size", "12px")
            .style("fill", "black");

        simulation.on("tick", () => {
            link.attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            linkLabels.attr("x", d => (d.source.x + d.target.x) / 2)
                      .attr("y", d => (d.source.y + d.target.y) / 2);

            node.attr("cx", d => d.x)
                .attr("cy", d => d.y);

            labels.attr("x", d => d.x)
                  .attr("y", d => d.y + 25);
        });
    }

    function dragStarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    function dragEnded(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }

    renderGraph();

    // Function to scan a URL and dynamically add it to the visualization
    function scanAndVisualize(targetURL) {
        // Check if we've reached the max node limit
        if (nodes.length >= 10) {
            alert("Node limit reached 10. Clear the graph before adding more nodes.");
            return;
        }

        // Ensure the targetURL is valid
        if (!targetURL) {
            console.error("No target URL found in scan summary.");
            return;
        }

        // Prevent duplicate nodes (ensure each entered URL appears only once)
        if (nodes.some(node => node.id === targetURL)) {
            console.log("Duplicate URL detected, not adding:", targetURL);
            return;
        }

        loadingMessage.style.display = "block";
        loadingMessage.innerText = "Scanning in progress...";
    
        // Start SSRF Scan
        fetch("/crawl", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: targetURL })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error("Network response was not ok.");
            }
            return response.json();
        })
        .then(data => {
            loadingMessage.innerText = "Scan complete! Fetching results...";
            console.log("SSRF Scan Response:", data);

            if (data.error) {
                alert("Error: " + data.error);
                loadingMessage.style.display = "none";
                return;
            }

            // Store scan results for this scanned URL
            scanDetails[targetURL] = {
                target: data.scan_summary.target_url,
                domain: data.scan_summary.domain,
                totalUrls: data.scan_summary.total_urls_scanned,
                confirmedSSRFVulnerabilities: data.scan_summary.confirmed_ssrf_vulnerabilities,
                potentialSSRFEndpoints: data.scan_summary.potential_ssrf_endpoints
            };

            descriptionBox.innerHTML = `
                <h4>Scan Summary</h4>
                <p><strong>Target:</strong> ${scanDetails[targetURL].target}</p>
                <p><strong>Domain:</strong> ${scanDetails[targetURL].domain}</p>
                <p><strong>Total URLs Scanned:</strong> ${scanDetails[targetURL].totalUrls}</p>
                <p><strong>Confirmed SSRF Vulnerabilites:</strong> ${scanDetails[targetURL].confirmedSSRFVulnerabilities}</p>
                <p><strong>Potential SSRF Endpoints:</strong> ${scanDetails[targetURL].potentialSSRFEndpoints}</p>
            `;

            // NEW ------------------------------------------------------------------------------------------------------------------------------------------------
            
            // Update charts using scan results
            updatePieChart(data.scan_summary.attack_type_distribution);
            updateBarChart(data.scan_summary.severity_distribution);

            // -----------------------------------------------------------------------------------------------------------------------------------------------------

            // Add scanned URL as a node
            nodes.push({
                id: targetURL,
                group: 1,
                risk: "medium", // Default risk level
                description: `Scanned target: ${targetURL}`,
            });

            links.push({
                source: "Web Server",
                target: targetURL,
                type: "Scan Target"
            });

            // Update graph visualization
            simulation.nodes(nodes);
            simulation.force("link").links(links);
            simulation.alpha(1).restart();
            renderGraph();

            loadingMessage.innerText = "Scan complete! Fetching results...";
        })
        .catch(error => {
            console.error("Scan Error:", error);
            loadingMessage.innerText = "Error: Scan failed.";
        });
    }

    // NEW -------------------------------------------------------------------------------------------------------------------------------------------------------
    
    // Function to update the Pie Chart for Attack Type Breakdown
    function updatePieChart(attackTypeData) {
        document.getElementById("attack-type-chart").style.display = "block";

        const ctx = document.getElementById("attackTypeChart").getContext("2d");

        new Chart(ctx, {
            type: "pie",
            data: {
                labels: Object.keys(attackTypeData),
                datasets: [{
                    label: "Count",
                    data: Object.values(attackTypeData),
                    backgroundColor: ["#FF6384", "#36A2EB", "#FFCE56", "#4CAF50", "#FF5722"]
                }]
            }
        });
    }

    // Function to update the Bar Chart for Severity Distribution
    function updateBarChart(severityData) {
        document.getElementById("severity-chart").style.display = "block";

        const ctx = document.getElementById("severityChart").getContext("2d");
       
        new Chart(ctx, {
            type: "bar",
            data: {
                labels: Object.keys(severityData),
                datasets: [{
                    label: "",
                    data: Object.values(severityData),
                    backgroundColor: ["#FF0000", "#FFA500", "#FFFF00", "#008000"], // Red, Orange, Yellow, Green
                }]
            },
            options: {
                plugins: {
                    legend: {
                        display: false // Hides the legend completely
                    }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
    }
    
    // -----------------------------------------------------------------------------------------------------------------------------------------------------------

    // function getStatusDescription(statusCode) {
    //     const statusDescriptions = {
    //         200: "OK - The request was successful.",
    //         301: "Moved Permanently - The URL has changed.",
    //         302: "Found - Redirected temporarily.",
    //         400: "Bad Request - Invalid input.",
    //         403: "Forbidden - Access is restricted.",
    //         404: "Not Found - The URL doesn't exist.",
    //         500: "Internal Server Error - The server encountered an issue."
    //     };
    //     return statusDescriptions[statusCode] || "Unknown Status";
    // }

    document.getElementById("scan-btn").addEventListener("click", function() {
        const url = document.getElementById("url-input").value;
        if (url) scanAndVisualize(url);
    });

    document.getElementById("url-input").addEventListener("keypress", function(event) {
        if (event.key === "Enter") {
            const url = document.getElementById("url-input").value;
            if (url) scanAndVisualize(url);
        }
    });
    document.getElementById("clear-btn").addEventListener("click", function() {
        // List of default nodes that should remain
        const defaultNodes = ["User", "Web Server", "Metadata Service", "Internal API"];
    
        // Filter out user-added nodes while keeping default nodes
        nodes = nodes.filter(node => defaultNodes.includes(node.id));
    
        // Remove links related to user-added nodes
        links = links.filter(link => defaultNodes.includes(link.source.id) && defaultNodes.includes(link.target.id));
    
        // Update and redraw the graph
        simulation.nodes(nodes);
        simulation.force("link").links(links);
        simulation.alpha(1).restart();
        renderGraph();
    
        console.log("User-added nodes cleared, default nodes remain.");
    
        // Show the clear message
        const clearMessage = document.getElementById("clear-message");
        clearMessage.style.display = "block";
    
        // Hide the message after 2 seconds
        setTimeout(() => {
            clearMessage.style.display = "none";
        }, 2000);
    });      
});
