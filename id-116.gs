/**
 * Estrategia para auditar la integración de Prevención de Pérdida de Datos (DLP).
 * Evalúa si existen reglas activas (rule.dlp o rule.system_defined_alerts) protegiendo a los usuarios.
 * Utiliza el Censo en RAM (O(1)) y el motor CEL para calcular la cobertura.
 */
class DataLossPreventionRulesStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-116",
        valueKey: "valorPrincipal",
        noteKey: "comentario116",
        riskKey: "riesgo116",
        scoreKey: "score116"
      }
    ];

    super("Data Loss Prevention (DLP) Audit", configIDs);
    this.category = "Drive"; 
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas no encontrados en memoria).");
    }

    const totalUsuarios = census.length;
    
    if (totalUsuarios === 0) {
      return this._buildErrorResponse("El censo está vacío. No hay usuarios para auditar.");
    }

    // 1. FILTRAR POLÍTICAS DE DLP Y ALERTAS DEL SISTEMA
    const dlpPolicies = policies.filter(p => p.setting && p.setting.type &&
      (p.setting.type.includes("rule.dlp") || p.setting.type.includes("rule.system_defined_alerts"))
    );

    let usuariosProtegidos = 0;

    // 2. CALCULAR COBERTURA EN EL CENSO
    // Si la organización no tiene DLP configurado, el bucle se omite (0 usuarios protegidos)
    if (dlpPolicies.length > 0) {
      for (const user of census) {
        // Usamos el motor CEL para evaluar si al usuario le aplica al menos UNA regla de DLP
        const aplicables = dlpPolicies.filter(p => CELParserEngine.evaluate(p, user));
        
        // A diferencia de contraseñas, las reglas DLP se acumulan. Con 1 basta para estar protegido.
        if (aplicables.length > 0) {
          usuariosProtegidos++;
        }
      }
    }

    const porcentajeNum = Math.round((usuariosProtegidos / totalUsuarios) * 100);

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta = `${porcentajeNum}%`;
    let riesgo116, comentario116;

    // Comentarios cortos y directos usando el formato "X de Y"
    if (usuariosProtegidos > 0) {
      riesgo116 = "Bajo";
      comentario116 = `${usuariosProtegidos} de ${totalUsuarios} usuarios están protegidos por reglas de Prevención de Pérdida de Datos (DLP) para notificar, advertir o bloquear fugas de información.`;
    } else {
      riesgo116 = "Alto";
      comentario116 = `0 de ${totalUsuarios} usuarios están protegidos por reglas de Prevención de Pérdida de Datos (DLP). La organización está expuesta a la exfiltración de datos sensibles.`;
    }

    // Trazabilidad técnica para la consola
    Logger.log(`[LOG] Data Loss Prevention (DLP) Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo116}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO
    return {
      name: this.name,
      valorPrincipal: respuestaConcreta,
      comentario116: comentario116,
      riesgo116: riesgo116,
      score116: this.calcularScoreDeRiesgo(riesgo116)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-116] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR_MEMORIA",
      riesgo116: "Medio",
      score116: 2,
      comentario116: msg
    };
  }
}