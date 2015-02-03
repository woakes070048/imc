//lat,lng,zoom,language,menu_filter_area are set outside
var imc_mod_map;
var imc_markers = [];
var infoWindow = new google.maps.InfoWindow({
  maxWidth: 350
});

function imc_mod_map_initialize() {
  var  center = new google.maps.LatLng(lat,lng);
  var mapOptions = {
    zoom: parseInt(zoom),
    center: center
  };
  imc_mod_map = new google.maps.Map(document.getElementById('imc-mod-map-canvas'),
      mapOptions);

  setMarkers(center, imc_mod_map);
}


function setMarkers(center, map) {
    var json = (function () { 
        var json = null;

        jQuery.ajax({ 
            'async': true, 
            'global': false, 
            'url': "index.php?option=com_imc&task=issues.markers&format=json", 
            'dataType': "json", 
            'success': function (data) {
                json = data; 

                //loop between each of the json elements
                for (var i = 0, length = json.data.length; i < length; i++) {
                    var data = json.data[i],
                    latLng = new google.maps.LatLng(data.latitude, data.longitude); 
                    // Create marker and putting it on the map
                    var marker = new google.maps.Marker({
                        position: latLng,
                        icon: data.category_image,
                        map: map,
                        title: data.title
                    });
                    if(data.category_image == '')
                      marker.setIcon('http://maps.google.com/mapfiles/ms/icons/red-dot.png');
                    
                    imc_markers.push(marker);
                    //bounds.extends(marker.position);

                    infoBox(map, marker, data);

                    if(data.state == 0){
                      marker.setIcon('http://maps.google.com/mapfiles/ms/icons/blue-dot.png');
                    }
                }
                resetBounds(map, imc_markers);

             }
        });
        return json;
    })();

}


function infoBox(map, marker, data) {
    
    // Attaching a click event to the current marker
    google.maps.event.addListener(marker, "click", function(e) {
        infoWindow.setContent('<div class="infowindowcontent">'+data.title+'</div>');
        infoWindow.open(map, marker);
        panelFocus(data.id);
    });
    google.maps.event.addListener(infoWindow,'closeclick',function(){
        panelFocusReset();
    });

    // Creating a closure to retain the correct data 
    // Pass the current data in the loop into the closure (marker, data)
    (function(marker, data) {
      // Attaching a click event to the current marker
      google.maps.event.addListener(marker, "click", function(e) {
        infoWindow.setContent('<div class="infowindowcontent">'+data.title+'</div>');
        infoWindow.open(map, marker);
      });
    })(marker, data);
}

// Add a marker to the map and push to the array.
function addMarker(location, map) {
  var marker = new google.maps.Marker({
    position: location,
    map: map
  });
  imc_markers.push(marker);
}

// Sets the map on all imc_markers in the array.
function setAllMap(map) {
  for (var i = 0; i < imc_markers.length; i++) {
    imc_markers[i].setMap(map);
  }
}

// Removes the imc_markers from the map, but keeps them in the array.
function clearMarkers() {
  setAllMap(null);
}

// Shows any imc_markers currently in the array.
function showMarkers() {
  setAllMap(imc_mod_map);
}

// Deletes all imc_markers in the array by removing references to them.
function deleteMarkers() {
  clearMarkers();
  imc_markers = [];
}

function resetBounds(map, gmarkers) {
  var a = 0;
  bounds = null;
  bounds = new google.maps.LatLngBounds();
  for (var i=0; i<gmarkers.length; i++) {
    if(gmarkers[i].getVisible()){
      a++;
      bounds.extend(gmarkers[i].position);  
    }
  }
  if(a > 0){
    map.fitBounds(bounds);
    var listener = google.maps.event.addListener(map, 'idle', function() { 
      if (map.getZoom() > 16) map.setZoom(16); 
      google.maps.event.removeListener(listener); 
    });
  }
}

function panelFocus(id) {
  var aTag = jQuery("a[name='imc-id-"+ id +"']");
  jQuery('html,body').animate({
      scrollTop: jQuery(aTag).offset().top
  }, 2000);

  //all
  jQuery("[id^=imc-panel-]").removeClass('imc-focus');
  jQuery("[id^=imc-panel-]").addClass('imc-not-focus');

  //selected
  jQuery('#imc-panel-'+id).removeClass('imc-not-focus');
  jQuery('#imc-panel-'+id).addClass('imc-focus');
  
}

function panelFocusReset() {
  jQuery("[id^=imc-panel-]").removeClass('imc-not-focus');
  jQuery("[id^=imc-panel-]").removeClass('imc-focus');
}