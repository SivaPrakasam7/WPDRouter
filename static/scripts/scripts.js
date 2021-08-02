function spliter(data){
    createwifi(data[1][0],data[1][1]);
    createcont(data[2]);
    alignforen(data[3][0]);
}

function ishow(id) {
    console.log(id);
    var arr = ["iwifi", "ipen", "iforen"];
    for (var i = 0; i < arr.length; i++) {
        if (arr[i] == id) {
            document.getElementById(id).style.display = "block";
        } else {
            document.getElementById(arr[i]).style.display = "none";
        }
    }
}

function iview(id) {
    if (document.getElementById(id).style.display == "none") {
        document.getElementById(id).style.display = "block";
    } else {
        document.getElementById(id).style.display = "none";
    }
}

function fview(id) {
    if (document.getElementById(id).style.display == "none") {
        document.getElementById(id).style.display = "block";
        document.getElementById("i" + id).src = "static/source/pic/down.png";
    } else {
        document.getElementById(id).style.display = "none";
        document.getElementById("i" + id).src = "static/source/pic/right.png";
    }
}

function closeview(id) {
    console.log(id);
    document.getElementById(id).remove();
}

function createwifi(wdata,data){
    var cont="";
    for (var key in wdata){
        var pic="";
        var count=0;
        if (wdata[key].info == null){
            info="Secure";
            pic="static/source/pic/wifi1.png";
        }else{
            info=wdata[key].info;
            pic="static/source/pic/wifi2.png";
        }
        try{
            if (data[0][1]==key){
                wdata[key].clients=data;
                for (var c in wdata[key].clients){
                    count=c;
                }
            }
        }catch{
            // pass
        }
        cont+="<div class='container' onclick='viewwifi(this.id," + JSON.stringify(wdata[key]) + ")' id='w" + wdata[key].bssid + "'><img class='cicon' src='"+pic+"'><table><tr><th>SSID</th><td>"+wdata[key].ssid+"</td></tr><tr><th>BSSID</th><td>"+wdata[key].bssid+"</td></tr><tr><th>DBM SIGNAL</th><td>"+wdata[key].dbm_signal+"</td></tr><tr><th>CHANNEL</th><td>"+wdata[key].channel+"</td></tr><tr><th>CRYPTO</th><td>"+wdata[key].crypto+"</td></tr><tr><th>RATE</th><td>"+wdata[key].rates+"</td></tr><tr><th>CLIENTS</th><td>"+count+"</td></tr><tr><th>INFO</th><td>"+info+"</td></tr></table></div>";
    }
    document.getElementById("wifis").innerHTML=cont;
}

function viewwifi(id, data) {
    var cont = "";
    var client = "";
    var pic = "";
    var icon = "";
    if (data.info == null) {
        info = "Secure";
        icon = "static/source/pic/wifi1.png";
    } else {
        info = data.info;
        icon = "static/source/pic/wifi2.png";
    }
    for (var c in data.clients) {
        client += c + ": " + data.clients[c][0] + " " + data.clients[c][1] + "<br>";
    }
    cont = "<table><tr><th colspan='2'>WIFI INFO</th></tr><tr><td>SSID</td><td>" + data.ssid + "</td></tr><tr><td>BSSID</td><td>" + data.bssid + "</td></tr><tr><td>DBM SIGNAL</td><td>" + data.dbm_signal + "</td></tr><tr><td>CHANNEL</td><td>" + data.channel + "</td></tr><tr><td>CRYPTO</td><td>" + data.crypto + "</td></tr><tr><td>RATE</td><td>" + data.rates + "</td></tr><tr><td>CLIENTS</td><td>" + client + "</td></tr><tr><td>INFO</td><td>" + info + "</td></tr></table>";
    document.getElementById("insertnow").innerHTML += "<div class='rshowlm' id='s" + id + "'><img src='" + icon + "' class='micon' /><img src='static/source/pic/close.png' onclick='closeview(\"s" + id + "\")' class='close'/><div class='rshowl'><div class='rshow'>" + cont + "</div?</div></div>";
}

function createcont(data){
    var cont="";
    document.getElementById("pentest").innerHTML="";
    for (var key in data){
        // cont+="<a class='notification' onclick='createpen(\""+key+"\","+JSON.stringify(data[key])+");' href='#view'><table width='100%' height='100%'><tr><td style='width: 20%;'><img class='nicon' src='static/source/pic/client.png'></td><td><table height='100%'><tr><td style='text-align: left; width: 30%;'>"+key+"</td></tr><tr><td style='text-align: left; width: 30%;'>"+info+"</td></tr></table></td><td style='text-align: right; padding-bottom: 2rem; color: rgba(238, 236, 236, 0.671);'>"+data[key].scan_time+"</td></tr></table></a>";
        try {
            // closeview("v"+String(key));
            alignpen(data[key]);
            // closeview("p" + key);
            // viewpen(String(key), data[key]);
        } catch (err) {
            console.log(err);
        }
    }
    // document.getElementById("clients").innerHTML=cont;
}

function createpen(ip,data){
    // console.log(data)
    // try{
    alignpen(ip,data);
    // }catch(err){ 
    //     console.log(err);
    // }
    try{
        var connections="";
        var portss="";
        var mounts="";
        for (var key in data.storage){
            mounts+=key+' ';
        }
        for (var key in data.process){
            con=data.process[key].connections
            for (var key in con){
                conn=con[key]
                for (var key in conn){
                    connections+=conn[key][0]+':'+conn[key][1]+' ';
                }
            }
        }
        for (var key in data.ports){
            portss+=key+' ';
        }
        if(data.evidence==null){
            evid=null
        }else{
            evid="Available";
        }
        try{
            mac=data.other.mac
        }catch{
            mac=null
        }
        cont="<div class='container' id='v"+ip+"' style='overflow-x:hidden;overflow-y:auto;'><div class='options'><a class='opt' href='"+data.jpath+"' download='"+ip+"_system.json'><img src='static/source/pic/json-file.png'></a><a  class='opt' onclick='viewpen(\""+ip+"\"," + JSON.stringify(data) + ")'><img src='static/source/pic/open.png'></a></div><table><tr><th>IP</th><td>"+ip+"</td></tr><tr><th>MAC</th><td>"+mac+"</td></tr><tr><th>SYSTEM</th><td>"+data.system+"</td></tr><tr><th>PROCESSOR</th><td>"+data.processor+"</td></tr><tr><th>INTERFACES</th><td>"+data.interfaces+"</td></tr><tr><th>MOUNTS</th><td>"+mounts+"</td></tr><tr><th>FILES</th><td>TOTAL "+data.files.total+", DUPLICTAES "+Object.keys(data.duplicates).length+"</td></tr><tr><th>RAM / CPU</th><td>"+data.ram+" / "+data.cpu_max+"</td></tr><tr><th>PROCESS COUNT</th><td>"+Object.keys(data.process).length+"</td></tr><tr><th>CONECTIONS</th><td>"+connections+"</td></tr><tr><th>PORTS</th><td>"+portss+"</td></tr><tr><th>LAST SCANNED</th><td>"+data.scan_time+"</td></tr><tr><th>ANALYSIS</th><td>"+data.analysis+"</td></tr><tr><th>EVIDENCE</th><td>"+evid+"</td></tr></table></div>";
    }catch (err){
        console.log(err)
        cont="<div class='container' id='v"+ip+"'>No details found scanning system scanning does not performed</div>";
    }
    document.getElementById("pentest").innerHTML+=cont;
}

function alignpen(pdata) {
    console.log(pdata);
    var cont = "";
    var warn = "";
    var pots = "";
    var pic = ""
    var ip=pdata.ipv4;
    if (pdata.osmatch == null) {
        osname = null;
        ostype = null;
        osaccuracy = null;
    } else {
        osname = pdata.osmatch.name;
        ostype = pdata.osmatch.type;
        osaccuracy = pdata.osmatch.accuracy;
    }
    for (var p in pdata.ports) {
        pots += pdata.ports[p].port + " ";
        if (pdata.ports[p].warning != null) {
            warn = "Danger";
            pic = "static/source/pic/pentest2.png";
        }
    }
    if (warn == "") {
        warn = "Secure";
        pic = "static/source/pic/pentest1.png";
    }
    cont += "<div class='container'><img src='" + pic + "' class='cicon' /><div class='options'><a class='opt' href='"+pdata.path+"' download='"+ip+"_port.json'><img src='static/source/pic/system.png'></a><a class='opt' href='"+pdata.jpath+"' download='"+ip+"_port.json'><img src='static/source/pic/download.png'></a><a  class='opt' onclick='viewpen1(\""+ip+"\"," + JSON.stringify(pdata) + ")'><img src='static/source/pic/open.png'></a></div><table><tr><td>IPv4</td><td>" + pdata.ipv4 + "</td></tr><tr><td>MAC</td><td>" + pdata.mac + "</td></tr><tr><td>NAME</td><td>" + pdata.name + "</td></tr><tr><td>OS MATCH</td><td>" + osname + "</td></tr><tr><td>OS TYPE</td><td>" + ostype + "</td></tr><tr><td>ACCURACY</td><td>" + osaccuracy + "</td></tr><tr><td>PORTS</td><td>" + pots + "</td></tr><tr><td>INFO</td><td>" + warn + "</td></tr></table></div>";
    // try {
    //     closeview("p1" + JSON.stringify(key));
    //     viewpen1(JSON.stringify(key), data[key].other);
    // } catch (err) {
    //     console.log(err);
    // }
    document.getElementById("pentest").innerHTML+=cont;
}

function viewpen(id,data){
    console.log(data)
    cont="<table>";
    for (var key in data){
        if(key == "process" | key =="storage" | key=="files" | key == "duplicates"){
            cont+="<tr><th colspan='2'>"+key+"</th></tr>";
            for (var k in data[key]){
                cont+="<tr><th colspan='2'>"+k+"</th></tr>";
                if (k == "detail"){
                    for (var k1 in data[key][k]){
                        cont+="<tr><th colspan='2'>"+k1+"</th></tr>";
                        for (var k2 in data[key][k][k1]){
                            cont+="<tr><td>"+k2+"</td><td>"+JSON.stringify(data[key][k][k1][k2])+"</td><tr>";
                        }
                    }
                }else{
                    cont+="<tr><td>"+k+"</td><td>"+JSON.stringify(data[key][k])+"</td><tr>";
                }
            }
        }
        else{
            cont+="<tr><td>"+key+"</td><td>"+data[key]+"</td><tr>";
        }
    }
    document.getElementById("insertnow").innerHTML += "<div class='rshowlm' id='p" + id + "'><img src='static/source/pic/system.png' class='micon' /><img src='static/source/pic/close.png' onclick='closeview(\"p" + id + "\")' class='close'/><div class='rshowl'><div class='rshow'>" + cont + "</div></div></div>";
}

function viewpen1(id, data) {
    var warn = "";
    var cont = "";
    var osd = "";
    var pot = "";
    var scp = "";
    var icon = "";
    if (data.osmatch == null) {
        osd = null
    } else {
        osd = "<table><tr><td>NAME</td><td>" + data.osmatch.name + "</td></tr><tr><td>OS FAMILY</td><td>" + data.osmatch.osfamily + "</td></tr><tr><td>TYPE</td><td>" + data.osmatch.type + "</td></tr><tr><td>ACCURACY</td><td>" + data.osmatch.accuracy + "</td></tr><tr><td>CPE</td><td>" + data.osmatch.cpe + "</td></tr></table>"
    }
    for (var p in data.ports) {
        for (var s in data.ports[p].scripts) {
            scp += "<table><tr><td>NAME</td><td>" + data.ports[p].scripts[s].name + "</td></tr><tr><td>DATA</td><td>" + JSON.stringify(data.ports[p].scripts[s].data) + "</td></tr><tr><td>RAW</td><td>" + data.ports[p].scripts[s].raw + "</td></tr></table>";
        }
        if (data.ports[p].warning != null) {
            warn = "Danger";
            icon = "static/source/pic/pentest2.png";
        }
        pot += "<table><tr><th colspan='2'>PORT " + data.ports[p].port + "</th></tr><tr><td>PRODUCT</td><td>" + data.ports[p].product + "</td></tr><tr><td>NAME</td><td>" + data.ports[p].name + "</td></tr><tr><td>VERSION</td><td>" + data.ports[p].version + "</td></tr><tr><td>STATE</td><td>" + data.ports[p].state + "</td></tr><tr><td>CPE</td><td>" + JSON.stringify(data.ports[p].cpe) + "</td></tr><tr><td>EXTRAINFO</td><td>" + data.ports[p].extrainfo + "</td></tr><tr><td>WARNING</td><td>" + warn + "</td></tr></table><table><tr><th colspan='2'>" + data.ports[p].port + " SCRIPTS</th></tr></table>" + scp;
    }
    if (warn == "") {
        warn = "Secure";
        icon = "static/source/pic/pentest1.png";
    }
    cont = "<div class='rshow'><table><tr><th colspan='2'>PEN-TEST INFO</th></tr><tr><td>IPv4</td><td>" + data.ipv4 + "</td></tr><tr><td>MAC</td><td>" + data.mac + "</td></tr><tr><td>NAME</td><td>" + data.name + "</td></tr><tr><td>INFO</td><td>" + warn + "</td></tr></table>" + osd + "<table></table>" + pot + "</div>";
    document.getElementById("insertnow").innerHTML += "<div class='rshowlm'  id='p1" + id + "'><img src='" + icon + "' class='micon' /><img src='static/source/pic/close.png' onclick='closeview(\"p1" + id + "\")' class='close'/><div class='rshowl'>" + cont + "</div></div>";
}

function alignforen(fdata) {
    var panel = document.getElementById("forensic");
    var cont = "";
    for (var key in fdata) {
        var pic = "";
        if (fdata[key][1] == null) {
            pic = "static/source/pic/folder1.png";
        } else {
            pic = "static/source/pic/folder2.png";
        }
        cont += "<div class='fld' onclick='viewforen(this.id," + JSON.stringify(fdata[key]) + ")' id='f" + key + "')'><img src='" + pic + "'>" + key + "</div>";
    }
    panel.innerHTML = cont;
}

function viewforen(id, data) {
    var cont = "<tr><th>S.NO</th><th>TYPE</th><th>TIME</th></tr>";
    var icon = "";
    var head = "";
    if (data[1] == null) {
        icon = "static/source/pic/forensic1.png";
    } else {
        icon = "static/source/pic/forensic2.png";
    }
    $.ajax({
        url: "/fileview/" + data[0],
        success: function(data) {
            for (var i = 0; i < data.length; i++) {
                var jdata = {};
                jsond = JSON.parse(JSON.stringify(data[i]));
                cjd = jsond.split(",");
                for (var j = 0; j < cjd.length; j++) {
                    ccjd = cjd[j].replace("{", "").replace("}", "").replaceAll("'", "").trim().split(": ");
                    jdata[ccjd[0].replace("'", "").replace(" ", "")] = ccjd[1];
                }
                try {
                    cont += "<tr onclick='fview(" + i + ")' href='#" + i + "'><td><img id='i" + i + "' src='static/source/pic/right.png' class='angle' />" + i + "</td><td>" + jdata.type + "</td><td>" + jdata.time + "</td></tr><tr style='display:none;' id=" + i + "><td align='center' colspan'=3'><table width='100%'><tr><th>PACKET</th></tr>";
                    for (var key in jdata) {
                        if (head == "") {
                            head = "<tr><th colspan='3'>" + jdata[key].toUpperCase() + " LOG</th></tr>";
                        }
                        cont += "<tr><td>" + key.toUpperCase() + "</td><td>" + jdata[key] + "</td></tr>";
                    }
                    cont += "</table></tr>";
                } catch (err) {
                    // pass
                }
            }
            document.getElementById("insertnow").innerHTML += "<div class='rshowlm' id='s" + id + "'><img src='" + icon + "' class='micon' /><img src='static/source/pic/close.png' onclick='closeview(\"s" + id + "\")' class='close'/><div class='rshowl'><div class='rshow'><table>" + head + cont + "</table></div></div></div>";
        }
    });
}