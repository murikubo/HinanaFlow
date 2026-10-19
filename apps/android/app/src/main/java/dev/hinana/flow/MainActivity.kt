package dev.hinana.flow

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                        Text("Hinana Flow", style = MaterialTheme.typography.headlineLarge)
                        Text("0.1.0 Alpha 1 · Android 골격")
                        Text("보안 설계 검토 대기 — 페어링과 전송이 비활성화되어 있습니다.")
                        Button(onClick = {}, enabled = false) { Text("파일 보내기") }
                    }
                }
            }
        }
    }
}
