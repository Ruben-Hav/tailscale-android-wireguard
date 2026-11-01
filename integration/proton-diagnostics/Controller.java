package com.tailscale.ipn.networktest;

import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import javax.net.ssl.*;
import org.json.*;
import libtailscale.Application;
import libtailscale.Libtailscale;
import libtailscale.LocalAPIResponse;
import libtailscale.ProtonStatusReceiver;

// A test-only, app-private controller. It never authenticates, logs out, clears
// data, changes the Tailscale account, or reads saved account credentials.
public final class Controller extends Instrumentation {
  private Bundle args;
  private Application backend;
  private volatile String state="Disconnected", error="";
  private String serverID, identity;
  private boolean originalAccelerator, settingsCaptured;
  @Override public void onCreate(Bundle a){super.onCreate(a);args=a;start();}
  void require(boolean ok,String message)throws Exception{if(!ok)throw new Exception(message);}
  String api(String method,String endpoint)throws Exception{
    LocalAPIResponse r=backend.callLocalAPI(15000,method,"/localapi/v0/"+endpoint,null);
    require(r.statusCode()==200,"Local API HTTP "+r.statusCode());
    return new String(r.bodyBytes(),StandardCharsets.UTF_8);
  }
  String identity()throws Exception{
    JSONObject self=new JSONObject(api("GET","status?peers=false")).getJSONObject("Self");
    byte[] digest=MessageDigest.getInstance("SHA-256").digest((self.optString("ID")+self.optString("PublicKey")).getBytes(StandardCharsets.UTF_8));
    StringBuilder out=new StringBuilder();for(int i=0;i<8;i++)out.append(String.format("%02x",digest[i]));return out.toString();
  }
  void await(String wanted)throws Exception{
    long end=SystemClock.elapsedRealtime()+45000;
    while(SystemClock.elapsedRealtime()<end){if(state.equals(wanted))return;if(!error.isEmpty())throw new Exception(error);Thread.sleep(25);}
    throw new Exception("Timeout waiting for "+wanted+", current "+state);
  }
  JSONObject stats()throws Exception{
    return new JSONObject().put("state",state).put("pid",Process.myPid()).put("uid",Process.myUid())
      .put("cpuMs",Process.getElapsedCpuTime()).put("elapsedMs",SystemClock.elapsedRealtime())
      .put("protonLoggedIn",Libtailscale.protonIsLoggedIn()).put("identityUnchanged",identity.equals(identity()))
      .put("nodeFingerprint",identity)
      .put("accelerator",Libtailscale.protonAcceleratorEnabled()).put("server",new JSONObject(Libtailscale.protonCurrentServer()));
  }
  JSONObject network()throws Exception{
    ConnectivityManager cm=(ConnectivityManager)getTargetContext().getSystemService(Context.CONNECTIVITY_SERVICE);
    JSONArray networks=new JSONArray();
    for(Network n:cm.getAllNetworks()){
      NetworkCapabilities caps=cm.getNetworkCapabilities(n);LinkProperties lp=cm.getLinkProperties(n);
      if(caps==null||lp==null)continue;
      JSONArray routes=new JSONArray();for(android.net.RouteInfo r:lp.getRoutes())routes.put(r.toString());
      networks.put(new JSONObject().put("vpn",caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)).put("routes",routes));
    }
    return new JSONObject().put("networks",networks);
  }
  JSONObject direct(String host,InetAddress address,boolean tls,boolean namedSni)throws Exception{
    long started=SystemClock.elapsedRealtime();JSONObject out=new JSONObject().put("host",host).put("address",address.getHostAddress()).put("tls",tls).put("namedSni",namedSni);
    Socket socket=new Socket();
    try{
      socket.connect(new InetSocketAddress(address,443),2500);socket.setSoTimeout(3500);
      out.put("connectMs",SystemClock.elapsedRealtime()-started).put("source",socket.getLocalAddress().getHostAddress());
      if(tls){
        SSLSocket ssl=(SSLSocket)((SSLSocketFactory)SSLSocketFactory.getDefault()).createSocket(socket,host,443,true);
        socket=ssl;SSLParameters p=ssl.getSSLParameters();p.setEndpointIdentificationAlgorithm("HTTPS");
        if(namedSni)p.setServerNames(Collections.singletonList(new SNIHostName("one.one.one.one")));
        ssl.setSSLParameters(p);ssl.startHandshake();out.put("handshakeMs",SystemClock.elapsedRealtime()-started);
        String path=(host.equals("1.1.1.1")||host.equals("www.cloudflare.com"))?"/cdn-cgi/trace":"/";
        ssl.getOutputStream().write(("GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        out.put("response",new BufferedReader(new InputStreamReader(ssl.getInputStream(),StandardCharsets.US_ASCII)).readLine());
      }
    }catch(Exception e){out.put("error",e.getClass().getSimpleName()+": "+e.getMessage());}
    finally{socket.close();}
    return out.put("ms",SystemClock.elapsedRealtime()-started);
  }
  JSONObject detail()throws Exception{
    JSONArray all=new JSONArray();
    for(String host:new String[]{"example.com","www.cloudflare.com","1.1.1.1"}){
      long begin=SystemClock.elapsedRealtime();InetAddress[] addresses=InetAddress.getAllByName(host);
      JSONArray order=new JSONArray();for(InetAddress a:addresses)order.put(a.getHostAddress());
      all.put(new JSONObject().put("host",host).put("resolveMs",SystemClock.elapsedRealtime()-begin).put("order",order));
      boolean v4=false,v6=false;
      for(InetAddress a:addresses){boolean is4=a instanceof Inet4Address;if(is4?v4:v6)continue;if(is4)v4=true;else v6=true;
        all.put(direct(host,a,true,false));
        if(host.equals("1.1.1.1"))all.put(direct(host,a,true,true));
      }
    }
    return new JSONObject().put("detail",all).put("network",network());
  }
  Object profile(String name,Class<?>[] types,Object...values)throws Exception{
    return Libtailscale.class.getMethod(name,types).invoke(null,values);
  }
  JSONObject command(String path,JSONObject body)throws Exception{
    switch(path){
      case "/state":return stats();
      case "/network":return network();
      case "/connect":
        if(body.has("serverID"))serverID=body.getString("serverID");error="";state="Connecting";Libtailscale.protonConnectServer(serverID);await("Connected");Thread.sleep(400);return stats();
      case "/servers":return new JSONObject().put("servers",new JSONArray(Libtailscale.protonListServers("NL")));
      case "/tailnet/stop":case "/tailnet/start":{
        Intent i=new Intent();i.setClassName("com.tailscale.ipn.debug","com.tailscale.ipn.IPNService");i.setAction(path.endsWith("stop")?"com.tailscale.ipn.STOP_VPN":"com.tailscale.ipn.START_VPN");if(path.endsWith("stop"))getTargetContext().startService(i);else getTargetContext().startForegroundService(i);Thread.sleep(500);return stats();
      }
      case "/disconnect":
        error="";state="Disconnecting";Libtailscale.protonDisconnect();await("Disconnected");return stats();
      case "/accelerator":Libtailscale.protonSetAcceleratorEnabled(body.getBoolean("enabled"));return stats();
      case "/detail":return detail();
      case "/url":{
        String host=body.getString("host");require(Arrays.asList("example.com","www.cloudflare.com","1.1.1.1").contains(host),"Unsupported test host");
        long begin=SystemClock.elapsedRealtime();JSONObject r=new JSONObject().put("host",host);HttpURLConnection c=(HttpURLConnection)new URL("https://"+host+(host.equals("example.com")?"/":"/cdn-cgi/trace")).openConnection();c.setConnectTimeout(10000);c.setReadTimeout(10000);c.setRequestProperty("Connection","close");
        if(body.optBoolean("freshTls")){SSLContext fresh=SSLContext.getInstance("TLS");fresh.init(null,null,null);((HttpsURLConnection)c).setSSLSocketFactory(fresh.getSocketFactory());}
        try{r.put("status",c.getResponseCode());try(InputStream in=c.getInputStream()){byte[] b=new byte[4096];while(in.read(b)!=-1){}}}catch(Exception e){r.put("error",e.getClass().getSimpleName()+": "+e.getMessage());}finally{c.disconnect();}
        return r.put("ms",SystemClock.elapsedRealtime()-begin);
      }
      case "/profile/start":profile("protonProfileStart",new Class<?>[]{String.class},body.getString("kind"));return stats();
      case "/profile/baseline":profile("protonProfileResetBaseline",new Class<?>[]{});return stats();
      case "/profile/stop":return new JSONObject((String)profile("protonProfileStop",new Class<?>[]{}));
      case "/trace/start":profile("protonTraceStart",new Class<?>[]{String.class},body.getString("addresses"));return stats();
      case "/trace/stop":return new JSONObject().put("packets",new JSONArray((String)profile("protonTraceStop",new Class<?>[]{})));
      case "/test/ipv6":profile("protonTestIPv6Available",new Class<?>[]{boolean.class},body.getBoolean("enabled"));return stats();
      case "/shutdown":try{profile("protonProfileStop",new Class<?>[]{});}catch(Exception ignored){}return stats();
      default:throw new Exception("Unknown test command");
    }
  }
  void control()throws Exception{
    try(ServerSocket server=new ServerSocket(39089,8,InetAddress.getByName("127.0.0.1"))){
      Bundle ready=new Bundle();ready.putString("stream","CONTROLLER READY "+stats()+"\n");sendStatus(0,ready);
      boolean running=true;
      while(running)try(Socket client=server.accept()){
        client.setSoTimeout(10000);BufferedReader in=new BufferedReader(new InputStreamReader(client.getInputStream(),StandardCharsets.UTF_8));
        String request=in.readLine();if(request==null)continue;String path=request.split(" ")[1];int length=0;String line;
        while((line=in.readLine())!=null&&!line.isEmpty())if(line.toLowerCase(Locale.ROOT).startsWith("content-length:"))length=Integer.parseInt(line.substring(15).trim());
        require(length>=0&&length<=8192,"Invalid command size");char[] chars=new char[length];int offset=0;while(offset<length){int n=in.read(chars,offset,length-offset);if(n<0)throw new EOFException();offset+=n;}
        JSONObject result;int status=200;
        try{result=command(path,length==0?new JSONObject():new JSONObject(new String(chars)));}
        catch(Throwable e){Throwable cause=e instanceof java.lang.reflect.InvocationTargetException?e.getCause():e;result=new JSONObject().put("error",cause.getClass().getSimpleName()+": "+cause.getMessage());status=500;}
        byte[] bytes=result.toString().getBytes(StandardCharsets.UTF_8);OutputStream out=client.getOutputStream();
        out.write(("HTTP/1.1 "+status+" OK\r\nContent-Type: application/json\r\nContent-Length: "+bytes.length+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));out.write(bytes);out.flush();
        running=!path.equals("/shutdown");
      }
    }
  }
  @Override public void onStart(){
    Bundle result=new Bundle();int code=0;
    try{
      Context ctx=getTargetContext(),app=ctx.getApplicationContext();backend=(Application)app.getClass().getMethod("getLibtailscaleApp").invoke(app);
      Intent start=new Intent();start.setClassName("com.tailscale.ipn.debug","com.tailscale.ipn.IPNService");start.setAction("com.tailscale.ipn.START_VPN");ctx.startForegroundService(start);
      long end=SystemClock.elapsedRealtime()+30000;while(SystemClock.elapsedRealtime()<end&&!new JSONObject(api("GET","status?peers=false")).optString("BackendState").equals("Running"))Thread.sleep(100);
      require(Libtailscale.protonIsLoggedIn(),"The saved Proton session is unavailable");identity=identity();originalAccelerator=Libtailscale.protonAcceleratorEnabled();settingsCaptured=true;
      serverID=args.getString("serverID");if(serverID==null)serverID=new JSONArray(Libtailscale.protonListServers("NL")).getJSONObject(0).getString("id");
      Libtailscale.setProtonStatusReceiver(new ProtonStatusReceiver(){public void onProtonState(String s){state=s;}public void onProtonError(long c,String s){error="Proton error "+c+": "+s;}});
      control();result.putString("stream","PASS: saved sessions preserved\n");
    }catch(Throwable e){code=1;result.putString("stream",android.util.Log.getStackTraceString(e));}
    finally{if(settingsCaptured)try{Libtailscale.protonSetAcceleratorEnabled(originalAccelerator);}catch(Exception ignored){}}
    finish(code,result);
  }
}
