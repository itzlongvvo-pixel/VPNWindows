<!--
  Nera VPN™
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
  Nera VPN™ is a trademark of Vio Holdings LLC.
  This software is proprietary and confidential. Unauthorized copying,
  distribution, modification, or use of this software, via any medium,
  is strictly prohibited without written permission from the copyright holder.
  The source code and binaries are protected by copyright law and international treaties.
-->
<script>
    import { onMount, onDestroy } from "svelte";
    import Globe from "globe.gl";
    import * as topojson from "topojson-client";

    let container;
    let globe;

    // Markers
    const MARKERS = [
        { city: "Tokyo", lat: 35.6, lng: 139.6 },
        { city: "Los Angeles", lat: 34.05, lng: -118.24 },
    ];

    export let focusLocation = null;

    $: if (globe && focusLocation) {
        // Fly to location
        globe.pointOfView(
            {
                lat: focusLocation.lat,
                lng: focusLocation.lng,
                altitude: 2.5, // Keep default altitude (no zoom)
            },
            2000,
        ); // 2-second animation

        // Disable auto-rotate while focused for stability
        globe.controls().autoRotate = false;
    } else if (globe && !focusLocation) {
        // Reset to default view or just resume rotation
        globe.controls().autoRotate = true;
        // Optional: Return to default altitude
        globe.pointOfView({ altitude: 2.5 }, 2000);
    }

    onMount(async () => {
        if (!container) return;

        // Get container dimensions
        const width = container.clientWidth;
        const height = container.clientHeight;

        // Initialize Globe
        globe = Globe()(container)
            .width(width)
            .height(height)
            .backgroundColor("rgba(0,0,0,0)") // Transparent
            .showAtmosphere(true)
            .atmosphereColor("#22d3ee") // Cyan accent
            .atmosphereAltitude(0.15) // Soft, large halo
            // Remove default image to rely on polygons or use a null helper if needed,
            // but usually polygonsData sits on top.
            // User didn't specify globeImageUrl, but "solid continent look" usually implies
            // we act on the sphere. If we don't set an image, it might default or be black.
            // We'll leave the image unset (null) to have a "holographic" feel (just atmosphere and polygons).
            .globeImageUrl(null);

        // Customize Globe Material (Ocean)
        if (globe.globeMaterial()) {
            globe.globeMaterial().color.set("#1e293b"); // Deep Slate Blue
            globe.globeMaterial().transparent = true;
            globe.globeMaterial().opacity = 0.9;
        }

        // Auto-rotate settings
        globe.controls().autoRotate = true;
        globe.controls().autoRotateSpeed = 0.6;

        // Fetch Countries
        try {
            const res = await fetch(
                "//unpkg.com/world-atlas/countries-110m.json",
            );
            const countries = await res.json();

            // Convert TopoJSON to GeoJSON
            // Use 'land' instead of 'countries' to get only coastlines (no internal borders)
            const land = topojson.feature(
                countries,
                countries.objects.land,
            ).features;

            globe
                .polygonsData(land)
                .polygonCapColor(() => "#1e293b") // Dark Slate (Matte base)
                .polygonSideColor(() => "rgba(0,0,0,0)") // Hide sides
                .polygonStrokeColor(() => "#22c55e") // Glowing Cyan Coastlines
                .polygonAltitude(0.005);

            // Remove Glossy Reflections (Fixes glowing artifacts)
            setTimeout(() => {
                const scene = globe.scene();
                scene.traverse((obj) => {
                    if (obj.type === "Mesh" && obj.material) {
                        obj.material.shininess = 0; // Matte finish
                        obj.material.flatShading = true;
                    }
                });
            }, 1000);

            // Also set base globe material to matte
            if (globe.globeMaterial()) {
                globe.globeMaterial().shininess = 0;
            }
        } catch (err) {
            console.error("Failed to load globe data", err);
        }

        // Add Markers using HTML Elements for the glow effect
        globe
            .htmlElementsData(MARKERS)
            .htmlLat("lat")
            .htmlLng("lng")
            .htmlElement((d) => {
                const el = document.createElement("div");
                el.style.width = "8px";
                el.style.height = "8px";
                el.style.background = "#22c55e"; // Green
                el.style.borderRadius = "50%";
                el.style.boxShadow = "0 0 10px #22c55e"; // Green glow
                el.style.pointerEvents = "none"; // Let clicks pass through if needed
                return el;
            });

        // Handle Window Resize
        const handleResize = () => {
            if (container && globe) {
                globe.width(container.clientWidth);
                globe.height(container.clientHeight);
            }
        };
        window.addEventListener("resize", handleResize);

        return () => {
            window.removeEventListener("resize", handleResize);
        };
    });

    onDestroy(() => {
        // Cleanup if necessary
    });
</script>

<div class="globe-container" bind:this={container}></div>

<style>
    .globe-container {
        width: 100%;
        height: 100%;
        position: absolute;
        inset: 0;
        z-index: 0;
    }
</style>
