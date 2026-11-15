package com.example.merossinspector;

import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.view.View;
import android.widget.*;
import org.json.*;
import java.net.*;
import java.io.*;
import java.security.MessageDigest;
import java.util.UUID;
import java.util.concurrent.*;

public class MainActivity extends Activity {
    EditText ip, key; TextView result; Button on, off, refresh;
    ExecutorService worker = Executors.newSingleThreadExecutor();
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this); root.setOrientation(1); root.setPadding(32,36,32,24); root.setBackgroundColor(Color.WHITE);
        TextView title = new TextView(this); title.setText("Meross Inspector 0.1"); title.setTextSize(25); title.setTextColor(Color.BLACK); root.addView(title);
        TextView subtitle = new TextView(this); subtitle.setText("Diagnóstico y control local · misma WiFi"); root.addView(subtitle);
        ip = new EditText(this); ip.setSingleLine(true); ip.setHint("IP del enchufe (ej. 192.168.1.50)"); root.addView(ip);
        key = new EditText(this); key.setSingleLine(true); key.setHint("Clave local Meross (device key)"); key.setInputType(129); root.addView(key);
        refresh = button(root,"Diagnosticar y medir", () -> query());
        on = button(root,"Encender", () -> toggle(1));
        off = button(root,"Apagar", () -> toggle(0));
        result = new TextView(this); result.setTextColor(Color.DKGRAY); result.setTextSize(16); result.setPadding(0,24,0,0); result.setText("Introduce la IP y la clave local del dispositivo. No se envían a ningún servidor externo."); root.addView(result);
        ScrollView scroll = new ScrollView(this); scroll.addView(root); setContentView(scroll);
    }
    Button button(LinearLayout parent, String label, Runnable action) { Button b=new Button(this); b.setText(label); parent.addView(b); b.setOnClickListener(v->action.run()); return b; }
    void status(String s) { runOnUiThread(() -> result.setText(s)); }
    void runTask(Callable<String> job) { status("Consultando dispositivo..."); worker.submit(() -> { try {status(job.call());} catch(Exception e){status("Error: "+e.getMessage()+"\nComprueba IP, WiFi, clave y compatibilidad HTTP local.");} }); }
    void query() { runTask(() -> {
        long start=System.currentTimeMillis();
        JSONObject all=request("Appliance.System.All","GET",new JSONObject());
        long ms=System.currentTimeMillis()-start;
        StringBuilder out=new StringBuilder("Respuesta local: "+ms+" ms\n\n");
        JSONObject data=all.optJSONObject("payload"); JSONObject a=data==null?null:data.optJSONObject("all");
        if(a!=null) {
            JSONObject sys=a.optJSONObject("system");
            if(sys!=null) {JSONObject hw=sys.optJSONObject("hardware"); if(hw!=null) out.append("Modelo: ").append(hw.optString("type","desconocido")).append("\n");}
            JSONObject control=a.optJSONObject("control");
            if(control!=null) {JSONObject toggle=control.optJSONObject("toggle"); if(toggle==null) toggle=control.optJSONObject("togglex"); if(toggle!=null) out.append("Estado: ").append(toggle.optInt("onoff")==1?"ENCENDIDO":"APAGADO").append("\n");}
        }
        try {
            JSONObject payload=new JSONObject().put("electricity",new JSONObject().put("channel",0));
            JSONObject electricity=request("Appliance.Control.Electricity","GET",payload).getJSONObject("payload").getJSONObject("electricity");
            out.append("Potencia: ").append(electricity.optDouble("power")/1000).append(" W\n");
            out.append("Tensión: ").append(electricity.optDouble("voltage")/10).append(" V\n");
            out.append("Intensidad: ").append(electricity.optDouble("current")/1000).append(" A\n");
        } catch(Exception unsupported) {out.append("Medición no disponible en este modelo o firmware.\n");}
        return out.toString();
    }); }
    void toggle(int value) { runTask(() -> {
        JSONObject payload=new JSONObject().put("toggle",new JSONObject().put("channel",0).put("onoff",value));
        JSONObject response=request("Appliance.Control.Toggle","SET",payload);
        return "Respuesta del dispositivo: "+response.optJSONObject("header").optString("method")+"\n"+(value==1?"Orden de encendido enviada":"Orden de apagado enviada")+"\nPulsa Diagnosticar para verificar el estado.";
    }); }
    JSONObject request(String namespace,String method,JSONObject payload) throws Exception {
        String host=ip.getText().toString().trim(), secret=key.getText().toString().trim();
        if(!host.matches("[0-9.]+") || host.length()>15) throw new Exception("Introduce una dirección IPv4 válida.");
        String[] parts=host.split("\\."); if(parts.length!=4) throw new Exception("IPv4 incorrecta");
        for(String p:parts) if(Integer.parseInt(p)>255 || Integer.parseInt(p)<0) throw new Exception("IPv4 incorrecta");
        if(secret.isEmpty()) throw new Exception("Falta la clave local Meross");
        String messageId=UUID.randomUUID().toString().replace("-", ""); long timestamp=System.currentTimeMillis()/1000;
        JSONObject header=new JSONObject().put("messageId",messageId).put("namespace",namespace).put("method",method).put("payloadVersion",1).put("from","/app/merossinspector/subscribe").put("timestamp",timestamp).put("sign",md5(messageId+secret+timestamp));
        JSONObject request=new JSONObject().put("header",header).put("payload",payload);
        HttpURLConnection conn=(HttpURLConnection)new URL("http://"+host+"/config").openConnection();
        conn.setRequestMethod("POST"); conn.setConnectTimeout(3000); conn.setReadTimeout(4000); conn.setDoOutput(true); conn.setRequestProperty("Content-Type","application/json");
        try {try(OutputStream os=conn.getOutputStream()){os.write(request.toString().getBytes("UTF-8"));}
            int code=conn.getResponseCode(); if(code!=200) throw new IOException("HTTP "+code);
            ByteArrayOutputStream bytes=new ByteArrayOutputStream(); try(InputStream is=conn.getInputStream()){byte[] buf=new byte[4096]; int n; while((n=is.read(buf))!=-1){if(bytes.size()>1024*1024) throw new IOException("Respuesta demasiado grande");bytes.write(buf,0,n);}}
            JSONObject response=new JSONObject(bytes.toString("UTF-8"));
            JSONObject rh=response.optJSONObject("header"); if(rh==null) throw new IOException("Respuesta sin cabecera");
            if("ERROR".equals(rh.optString("method"))) throw new IOException("Dispositivo rechazó solicitud: "+response.optJSONObject("payload"));
            if(!messageId.equals(rh.optString("messageId"))) throw new IOException("Identificador de respuesta inesperado");
            return response;
        } finally {conn.disconnect();}
    }
    static String md5(String s) throws Exception {byte[] hash=MessageDigest.getInstance("MD5").digest(s.getBytes("UTF-8"));StringBuilder sb=new StringBuilder();for(byte b:hash)sb.append(String.format("%02x",b&255));return sb.toString();}
    @Override protected void onDestroy(){worker.shutdownNow();super.onDestroy();}
}
