document.addEventListener("DOMContentLoaded", function() {
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

    const descriptionBox = d3.select("#description");

    // Define colors based on risk level
    const riskColors = {
        "low": "blue",
        "medium": "yellow",
        "high": "red"
    };

    let nodes = [
        { id: "User", group: 1, risk: "low", description: "End user making a request." },
        { id: "Web Server", group: 2, risk: "medium", description: "Processes user requests." },
        { id: "Internal API", group: 3, risk: "high", description: "Sensitive internal API." },
        { id: "Metadata Service", group: 3, risk: "high", description: "Cloud metadata service (Common SSRF Target)." }
    ];

    let links = [
        { source: "User", target: "Web Server", type: "User Request" },
        { source: "Web Server", target: "Internal API", type: "API Call" },
        { source: "Web Server", target: "Metadata Service", type: "Metadata Access" }
    ];

    const simulation = d3.forceSimulation(nodes)
        .force("link", d3.forceLink(links).id(d => d.id).distance(150))
        .force("charge", d3.forceManyBody().strength(-200))
        .force("collide", d3.forceCollide(50))
        .force("center", d3.forceCenter(width / 2, height / 2));

    function renderGraph() {
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
                descriptionBox.html(`
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
                `);
            });

        // Add node labels
        const labels = svg.selectAll(".label")
            .data(nodes)
            .enter().append("text")
            .attr("class", "label")
            .attr("text-anchor", "middle")
            .attr("dy", 30)
            .text(d => d.id)
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
        // Prevent duplicate nodes
        if (nodes.some(node => node.id === targetURL)) {
            console.log("Duplicate URL detected, not adding:", targetURL);
            return;
        }
    
        fetch("/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: targetURL })
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 200) {
                const newNode = {
                    id: data.url,
                    group: 4,
                    risk: "high",
                    description: "Scanned external resource. Potential SSRF risk."
                };
                const newLink = { source: "Web Server", target: data.url, type: "Possible SSRF Exploit" };
    
                nodes.push(newNode);
                links.push(newLink);
    
                simulation.nodes(nodes);
                simulation.force("link").links(links);
                simulation.alpha(1).restart();
    
                renderGraph();
            }
        })
        .catch(error => console.error("Scan Error:", error));
    }

    // Handle user input for scanning
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

    function fetchLatestScans() {
        fetch("/get_scanned_urls")
        .then(response => response.json())
        .then(data => {
            data.forEach(url => {
                if (!nodes.some(node => node.id === url)) {
                    scanAndVisualize(url);
                }
            });
        })
        .catch(error => console.error("Error fetching scan results:", error));
    }
    
    // Check for new scans every 5 seconds
    setInterval(fetchLatestScans, 5000);    
});
