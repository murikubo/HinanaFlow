package dev.hinana.flow

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import dev.hinana.flow.core.StoredFile
import kotlinx.coroutines.*

class MainActivity:ComponentActivity() {
    private lateinit var model:FlowModel
    private lateinit var foregroundImport:ForegroundImport
    private var exportData:ByteArray?=null
    private val activityWork=CoroutineScope(SupervisorJob()+Dispatchers.Main.immediate)
    private val importer=registerForActivityResult(object:ActivityResultContracts.OpenDocument(){
        override fun createIntent(context:Context,input:Array<String>):Intent=super.createIntent(context,input).putExtra(Intent.EXTRA_LOCAL_ONLY,true)
    }){uri->foregroundImport.result(uri)}
    private val exporter=registerForActivityResult(object:ActivityResultContracts.CreateDocument("application/octet-stream"){
        override fun createIntent(context:Context,input:String):Intent=super.createIntent(context,input).putExtra(Intent.EXTRA_LOCAL_ONLY,true)
    }){uri->
        val bytes=exportData;exportData=null
        if(uri==null || bytes==null){bytes?.fill(0);model.exported(false)}else activityWork.launch{
            val success=withContext(Dispatchers.IO){runCatching{
                check(uri.scheme=="content")
                contentResolver.openOutputStream(uri,"w")?.use{it.write(bytes);it.flush()}?:error("HF-F-DEST")
            }.isSuccess};bytes.fill(0);model.exported(success)
        }
    }
    private val lanPermission=registerForActivityResult(ActivityResultContracts.RequestPermission()){granted->
        model.notice(if(granted)"로컬 네트워크 허용됨 — 직접 다시 시작하세요" else "로컬 네트워크 권한이 거부됐습니다")
    }
    private fun ensureLan():Boolean {
        val permission="android.permission.ACCESS_LOCAL_NETWORK"
        if(Build.VERSION.SDK_INT>=37 && ContextCompat.checkSelfPermission(this,permission)!=PackageManager.PERMISSION_GRANTED){lanPermission.launch(permission);return false}
        return true
    }
    override fun onCreate(savedInstanceState:Bundle?){
        super.onCreate(savedInstanceState);model=FlowModel(application)
        foregroundImport=ForegroundImport(lifecycle,
            activate={model.setActive(true)},
            consume={model.stageFile(it)},
            cancelled={model.notice("파일 선택 취소 — 다시 선택하세요")})
        setContent{MaterialTheme{SharingScreen(model,
            browse={if(ensureLan())model.browse()},listen={if(ensureLan())model.listen()},
            connect={send,manual->if(ensureLan())model.connect(send,manual)},
            pick={model.stop("사용자 파일 선택 중");importer.launch(arrayOf("*/*"))},
            export={file->model.stop();model.exportBytes(file)?.let{bytes->exportData?.fill(0);exportData=bytes;exporter.launch(file.name)}})}}
    }
    override fun onPause(){if(::foregroundImport.isInitialized)foregroundImport.pause();if(::model.isInitialized)model.setActive(false);super.onPause()}
    override fun onDestroy(){if(::model.isInitialized)model.dispose();exportData?.fill(0);exportData=null;activityWork.cancel();super.onDestroy()}
}

@Composable private fun SharingScreen(model:FlowModel,browse:()->Unit,listen:()->Unit,connect:(Boolean,Boolean)->Unit,pick:()->Unit,export:(StoredFile)->Unit) {
    var diagnosis by remember{mutableStateOf(false)}
    var received by remember{mutableStateOf(false)}
    Surface(Modifier.fillMaxSize()){
        Column(Modifier.windowInsetsPadding(WindowInsets.safeDrawing).imePadding().verticalScroll(rememberScrollState()).padding(20.dp),verticalArrangement=Arrangement.spacedBy(14.dp)){
            Text("Hinana Flow",style=MaterialTheme.typography.headlineLarge)
            Text("0.1.0 Alpha 1 · Android ↔ Apple 연동")
            Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
                Text(model.status,style=MaterialTheme.typography.titleMedium)
                if(model.busy)Button(onClick={model.stop("사용자가 연결·대기를 종료했습니다")}){Text("연결·대기 종료")}
            }}
            if(model.fingerprint.isEmpty())Button(onClick={model.prepare()},enabled=!model.preparing && !model.busy){Text("신원 생성 또는 불러오기")}
            if(model.preparing)LinearProgressIndicator(Modifier.fillMaxWidth())
            if(model.fileConsent.isNotEmpty())Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp)){
                Text("파일이 도착했어요");Text(model.fileConsent)
                Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){
                    Button(onClick={model.decideFile(true)}){Text("파일 받기")}
                    OutlinedButton(onClick={model.decideFile(false)}){Text("거절")}
                }
            }}
            if(model.textConsent.isNotEmpty())Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp)){
                Text(model.textConsent)
                Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){
                    Button(onClick={model.decideText(true)}){Text("이번 텍스트 수신 승인")}
                    OutlinedButton(onClick={model.decideText(false)}){Text("거절")}
                }
            }}
            Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){
                OutlinedButton(onClick={received=!received;if(received)model.refreshFiles()},enabled=!model.preparing){Text(if(received)"공유" else "받은 파일")}
                OutlinedButton(onClick={diagnosis=!diagnosis}){Text(if(diagnosis)"진단 닫기" else "기기 확인·진단")}
            }
            if(diagnosis || (model.fingerprint.isNotEmpty() && !model.storedTrust))Card(Modifier.fillMaxWidth()){Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
                Text("전체 지문을 상대 화면과 직접 대조하세요")
                Text("내 공개키 지문");SelectionContainer{Text(model.fingerprint,fontFamily=FontFamily.Monospace)}
                Text("Android Keystore: ${model.hardware} · 개인 키 추출 불가")
                if(model.storedTrust)Text("저장된 상대 키 사용 · 발견 이름은 신뢰 근거가 아닙니다")
                OutlinedTextField(value=model.expected,onValueChange={model.expected=it;model.oob=false},label={Text("다른 기기의 ‘내 공개키 지문’ 64자리")},
                    singleLine=true,
                    keyboardOptions=androidx.compose.foundation.text.KeyboardOptions(autoCorrectEnabled=false,keyboardType=androidx.compose.ui.text.input.KeyboardType.Ascii),
                    supportingText={if(model.expected.isNotEmpty() && model.expected.equals(model.fingerprint,ignoreCase=true))Text("내 지문이 입력됐습니다. 다른 기기 화면의 지문을 넣어주세요.",color=MaterialTheme.colorScheme.error)},
                    enabled=!model.busy && !model.preparing,modifier=Modifier.fillMaxWidth())
                Row{Checkbox(checked=model.oob,onCheckedChange={model.oob=it},enabled=!model.busy && !model.preparing);Text("상대 화면의 전체 지문을 직접 확인했습니다")}
                Text("OOB 확인만으로 신뢰가 저장되지 않습니다. 실제 상호 TLS 인증 후 저장합니다.",style=MaterialTheme.typography.bodySmall)
            }}
            if(received){
                Text("검증 저장 파일",style=MaterialTheme.typography.titleLarge)
                Button(onClick={model.refreshFiles()},enabled=!model.busy && !model.preparing){Text("목록 새로 고침")}
                if(model.files.isEmpty())Text("표시할 완료 파일이 없습니다")
                model.files.forEach{file->Card(Modifier.fillMaxWidth()){Column(Modifier.padding(12.dp)){
                    Text(file.name);Text("${file.size} bytes")
                    Button(onClick={export(file)},enabled=!model.busy && !model.preparing){Text("저장 위치 선택")}
                }}}
            }else{
                Text("보내기",style=MaterialTheme.typography.titleLarge)
                Button(onClick=browse,enabled=model.fingerprint.isNotEmpty()&&!model.connected&&!model.preparing){Text("주변 기기 찾기 (60초)")}
                model.peers.forEach{peer->OutlinedButton(onClick={model.selected=peer},enabled=!model.connected&&!model.preparing,modifier=Modifier.fillMaxWidth()){
                    Text(peer.label+(if(model.selected?.id==peer.id)" · 선택됨" else "")+"\n발견 이름 · 연결 전 미확인")
                }}
                model.selected?.let{peer->
                    Text("선택: ${peer.label} · 보낼 때 다시 해석·인증합니다")
                    OutlinedButton(onClick=pick,enabled=!model.preparing){Text("파일 선택 (10,000,000바이트 이하)")}
                    Button(onClick={connect(true,false)},enabled=model.prepared&&!model.connected&&!model.preparing){Text("선택 파일 보내기")}
                    OutlinedButton(onClick={connect(false,false)},enabled=!model.connected&&!model.preparing){Text("선택 기기에 TLS 연결")}
                }
                Text("받기",style=MaterialTheme.typography.titleLarge)
                Button(onClick=listen,enabled=model.fingerprint.isNotEmpty()&&!model.busy&&!model.preparing){Text("받기 대기 (전면 60초)")}
                if(model.connected){
                    OutlinedTextField(value=model.draft,onValueChange={model.draft=it},label={Text("승인 후 보낼 짧은 텍스트")},modifier=Modifier.fillMaxWidth())
                    Button(onClick={model.sendText()},enabled=model.draft.isNotEmpty()){Text("텍스트 전송 제안")}
                }
                if(model.receivedText.isNotEmpty()){Text("받은 텍스트");SelectionContainer{Text(model.receivedText)}}
            }
            if(model.fileSummary.isNotEmpty())Text(model.fileSummary)
            if(diagnosis){
                Text("Bonjour 실패 시 수동 LAN 연결")
                OutlinedTextField(value=model.manualHost,onValueChange={model.manualHost=it},label={Text("상대 IPv4")},enabled=!model.busy)
                OutlinedTextField(value=model.manualPort,onValueChange={model.manualPort=it},label={Text("상대 포트")},enabled=!model.busy)
                OutlinedButton(onClick={connect(false,true)},enabled=model.fingerprint.isNotEmpty()&&!model.busy&&!model.preparing){Text("수동 TLS 연결")}
            }
            Text("같은 Wi-Fi에서 앱을 열어 둔 동안만 공유합니다. 화면 잠금·다른 앱 전환 시 연결과 요청을 정리하며 자동 재연결하지 않습니다.",style=MaterialTheme.typography.bodySmall)
        }
    }
}
