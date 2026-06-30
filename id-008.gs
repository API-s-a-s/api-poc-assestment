/**
 * Estrategia de Adopción de Verificación en Dos Pasos (2SV).
 * Propósito: Auditar cuántos usuarios REALMENTE tienen configurado el 2SV en sus cuentas.
 * Utiliza el Censo en RAM (Directory API) para obtener telemetría en tiempo real
 */
class TwoStepVerificationCounter extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-008", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario008",
        riskKey: "riesgo008",
        scoreKey: "score008"
      }
    ];

    super("2-Step Verification Adoption Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census } = globalContext;

    if (!census) {
      return this._buildErrorResponse("Falta el contexto global (censo).");
    }

    // =======================================================================
    // PASO 1: VALIDAR EL ESTADO DEL CENSO
    // =======================================================================
    const totalUsuarios = census.length;

    if (totalUsuarios === 0) {
      Logger.log("[DEBUG ID-008] ALERTA: El censo de usuarios está vacío.");
      return {
        name: this.name,
        valorPrincipal: "empty.",
        comentario008: "omitió datos.",
        riesgo008: "",
        score008: ""
      };
    }

    // =======================================================================
    // PASO 2: CÁLCULO DE ADOPCIÓN (TIEMPO REAL) Y RECOLECCIÓN DE AFECTADOS
    // =======================================================================
    let usuariosCon2SV = 0;
    let usuariosSin2SVList = []; // NUEVO: Arreglo para guardar los usuarios vulnerables

    for (const user of census) {
      if (user.isEnrolledIn2Sv === true) {
        usuariosCon2SV++;
      } else {
        // Guardamos el email de los que NO tienen activa la verificación en 2 pasos
        usuariosSin2SVList.push(user.email || user.id);
      }
    }

    const porcentajeNum = Math.round((usuariosCon2SV / totalUsuarios) * 100);
    const estadoPrincipal = `${porcentajeNum}%`; // Imprimiremos el % en la celda principal
    
    Logger.log(`[ID-008] Censo procesado. Usuarios: ${totalUsuarios} | Con 2SV: ${usuariosCon2SV} | Adopción: ${porcentajeNum}%`);

    // NUEVO: Imprimimos el log de los usuarios afectados para auditoría forense
    if (usuariosSin2SVList.length > 0) {
      Logger.log(`[ID-008] DETALLE: Usuarios SIN Verificación en Dos Pasos activa (Vulnerables): ${usuariosSin2SVList.join(", ")}`);
    }

    // =======================================================================
    // PASO 3: ASIGNACIÓN DE RIESGOS Y CONSTRUCCIÓN DE SALIDA
    // =======================================================================
    let riesgo = "Medio";
    let comentario;

    if (porcentajeNum === 0) {
      riesgo = "Alto";
      comentario = `Ningún usuario cuenta con verificación en dos pasos operativa. ${usuariosCon2SV}/${totalUsuarios}.`;
    } else if (porcentajeNum === 100) {
      riesgo = "Bajo";
      comentario = `El 100% de los usuarios de las identidades auditadas tienen la verificación en dos pasos (MFA) operativa. ${usuariosCon2SV}/${totalUsuarios}`;
    } else {
      riesgo = "Medio";
      comentario = `Adopción fragmentada. El ${porcentajeNum}% de los usuarios tiene el 2FA activo. ${usuariosCon2SV}/${totalUsuarios}.`;
    }

    return {
      name: this.name,
      valorPrincipal: estadoPrincipal,
      comentario008: comentario,
      riesgo008: riesgo,
      score008: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  // Traductor de texto a número (Score)
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return "";
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return "";
  }

  // Handler de errores en memoria
  _buildErrorResponse(msg) {
    Logger.log(`[ID-008] ERROR: ${msg}`);
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo008: "",
      score008: "",
      comentario008: msg
    };
  }
}