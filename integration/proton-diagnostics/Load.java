package com.tailscale.ipn.loadtest;

import android.app.Instrumentation;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import java.io.*;
import java.net.*;
import org.json.JSONObject;

// This APK has a distinct UID/process and no access to Protonscale credentials.
public final class Load extends Instrumentation {
  private Bundle args;
  @Override public void onCreate(Bundle a){super.onCreate(a);args=a;start();}
  @Override public void onStart(){
    Bundle result=new Bundle();
    try{
      if(args.getString("mode","").equals("probe")){
        String host=args.getString("host","example.com");if(!java.util.Arrays.asList("example.com","www.cloudflare.com","1.1.1.1").contains(host))throw new IOException("Unsupported host");
        long began=SystemClock.elapsedRealtime();HttpURLConnection c=(HttpURLConnection)new URL("https://"+host+(host.equals("example.com")?"/":"/cdn-cgi/trace")).openConnection();c.setConnectTimeout(10000);c.setReadTimeout(10000);c.setRequestProperty("Connection","close");
        JSONObject r=new JSONObject().put("host",host).put("uid",Process.myUid()).put("pid",Process.myPid());try{r.put("status",c.getResponseCode());try(InputStream in=c.getInputStream()){byte[] b=new byte[4096];while(in.read(b)!=-1){}}}catch(Exception e){r.put("error",e.getClass().getSimpleName()+": "+e.getMessage());}finally{c.disconnect();}
        result.putString("stream",r.put("ms",SystemClock.elapsedRealtime()-began).toString()+"\n");finish(0,result);return;
      }
      boolean upload=args.getString("direction","download").equals("upload");int bytes=Integer.parseInt(args.getString("bytes","33554432"));int rate=Integer.parseInt(args.getString("rate","2097152"));
      String target=upload?"https://speed.cloudflare.com/__up":"https://speed.cloudflare.com/__down?bytes="+bytes+"&nonce="+System.nanoTime();
      HttpURLConnection c=(HttpURLConnection)new URL(target).openConnection();c.setConnectTimeout(10000);c.setReadTimeout(20000);c.setUseCaches(false);c.setRequestProperty("Accept-Encoding","identity");c.setRequestProperty("Connection","close");
      byte[] buffer=new byte[32768];new java.util.Random(42).nextBytes(buffer);long amount=0,start=SystemClock.elapsedRealtimeNanos(),cpu=Process.getElapsedCpuTime();
      if(upload){c.setRequestMethod("POST");c.setDoOutput(true);c.setFixedLengthStreamingMode(bytes);try(OutputStream out=c.getOutputStream()){while(amount<bytes){int n=(int)Math.min(bytes-amount,buffer.length);out.write(buffer,0,n);amount+=n;pace(start,amount,rate);}}}
      int status=c.getResponseCode();if(status!=200)throw new IOException("HTTP "+status);
      try(InputStream in=c.getInputStream()){int n;while((n=in.read(buffer))!=-1)if(!upload){amount+=n;pace(start,amount,rate);}}
      c.disconnect();if(amount!=bytes)throw new IOException("Incorrect byte count");
      result.putString("stream",new JSONObject().put("direction",upload?"upload":"download").put("bytes",amount).put("seconds",(SystemClock.elapsedRealtimeNanos()-start)/1e9).put("clientCpuMs",Process.getElapsedCpuTime()-cpu).put("pid",Process.myPid()).put("uid",Process.myUid()).toString()+"\n");finish(0,result);
    }catch(Throwable e){result.putString("stream",android.util.Log.getStackTraceString(e));finish(1,result);}
  }
  void pace(long start,long bytes,int rate)throws Exception{if(rate<=0)return;long left=start+bytes*1000000000L/rate-SystemClock.elapsedRealtimeNanos();if(left>0)Thread.sleep(left/1000000,(int)(left%1000000));}
}
