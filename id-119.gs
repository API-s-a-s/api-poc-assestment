/**
 * Estrategia para auditar la advertencia de invitación externa en Calendar.
 * Evalúa el parámetro warn_on_invite.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/calendar.external_invitations
 */
class CalendarExternalInvitationsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-119", 
        valueKey: "valorPrincipal",
        noteKey: "comentario119",
        riskKey: "riesgo119",
        scoreKey: "score119"
      }
    ];

    super("Calendar External Invitations Warning Audit", configIDs);
    this.category = "Servicios adicionales";
    this.customerId = customerId;
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
    const { policies, auth } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    // Filtramos las políticas pertenecientes al sub-entorno de Calendar (Advertencia de invitación externa)
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("calendar.external_invitations")
    );
    
    // DEBUG: Imprimir todas las políticas de Calendar en memoria
    const calendarTypes = policies.map(p => p.setting && p.setting.type).filter(t => t && t.toLowerCase().includes("calendar"));
    Logger.log(`[DEBUG ID-119] Políticas de calendar encontradas en memoria: ${JSON.stringify(calendarTypes)}`);
    Logger.log(`[ID-119] Se encontraron ${targetPolicies.length} políticas en memoria para este filtro.`);
    
    // Fallback: si no está en bulk, consultar directamente a la API (patrón id-113 / id-044)
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-119] [WARNING] La API masiva no trajo configuraciones para esta política. Consultando API directamente...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*calendar.external_invitations.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" }
        };

        const response = this.fetchWithBackoff(url, options);
        const json = JSON.parse(response.getContentText());
        targetPolicies = json.policies || [];
        Logger.log(`[ID-119] [SUCCESS] API directa retornó ${targetPolicies.length} políticas.`);
      } catch (e) {
        Logger.log(`[ID-119] Error al consultar la API directamente: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-119] Detalles de las políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedValue = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      // Resolvemos los conflictos utilizando el reductor por defecto
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "calendar.external_invitations");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Verificación resiliente soportando variantes de nomenclatura (snake_case y camelCase)
        if (valueNode.warn_on_invite !== undefined) {
            extractedValue = valueNode.warn_on_invite;
        } else if (valueNode.warnOnInvite !== undefined) {
            extractedValue = valueNode.warnOnInvite;
        }
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluamos la variable estricta de tipo Boolean
    if (extractedValue === true) {
      respuestaConcreta = "Activado";
      riesgo = "Bajo";
      comentario = "La advertencia de invitación externa está activada. Esto actúa como una barrera psicológica fundamental contra la ingeniería social, alertando proactivamente a los empleados cuando un usuario externo a la organización es añadido a una convocatoria.";
    } else if (extractedValue === false) {
      respuestaConcreta = "Desactivado";
      riesgo = "Alto";
      comentario = "La advertencia de invitación externa está desactivada. Esto facilita los ataques de 'Phishing de Calendario', permitiendo que invitaciones maliciosas validen correos corporativos y creen canales de comunicación directos sin alertas.";
    } else {
      // Fallback seguro: Si no se define una política explícita en la API, Google Workspace aplica el valor por defecto del sistema
      // el cual es ADVERTIR a los usuarios (equivalente a true).
      respuestaConcreta = "Activado (Valor por defecto)";
      riesgo = "Bajo";
      comentario = "No se encontraron políticas explícitas en la API para esta configuración. Se hereda el comportamiento predeterminado seguro de Google Workspace, el cual mantiene activada la advertencia al invitar usuarios externos.";
    }

    Logger.log(`[LOG] Calendar External Invitations Warning Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedValue}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario119: comentario,
      riesgo119: riesgo,
      score119: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-119] ERROR: ${msg}`);
    return { 
      name: this.name, 
      valorPrincipal: "ERROR", 
      riesgo119: "Medio", 
      score119: 2, 
      comentario119: msg 
    };
  }
}