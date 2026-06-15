package com.research.assistant.controller;
import com.research.assistant.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
@RestController
@RequestMapping("/api/chat")
@CrossOrigin(origins = "*")
public class ChatController {
    @Autowired private JwtUtil jwtUtil;
    @PostMapping("/ask")
    public ResponseEntity<?> ask(@RequestHeader(value="Authorization",required=false) String authHeader,
                                  @RequestBody Map<String,String> req) {
        if (authHeader==null||!authHeader.startsWith("Bearer ")) return ResponseEntity.status(401).body(Map.of("message","Please log in."));
        String token = authHeader.substring(7);
        if (!jwtUtil.validateToken(token)) return ResponseEntity.status(401).body(Map.of("message","Session expired."));
        String question = req.get("question");
        if (question==null||question.trim().isEmpty()) return ResponseEntity.badRequest().body(Map.of("message","Question cannot be empty."));
        // TODO: Connect your RAG pipeline here
        String answer = "Placeholder response for: \""+question+"\"\n\nConnect your RAG pipeline in ChatController.java to return real answers from your documents.";
        return ResponseEntity.ok(Map.of("answer",answer,"question",question));
    }
}
