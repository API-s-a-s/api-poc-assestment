/**
 * ID Evaluado: ID-180
 * Configuración Evaluada: Recuperación de cuentas - Verificación de propiedad del dominio (Registros DNS)
 * Filtro de Esquema / Búsqueda: Directory API (Domains)
 */
class DomainVerificationStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      {
        id: "ID-180",
        valueKey: "valorPrincipal",
        noteKey: "comentario180",
        riskKey: "riesgo180",
        scoreKey: "score180"
      }
    ];

    super("Domain Verification Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Preparar y supervisar"; 
  }

  /**
   * Mapeo de puntajes estándar de riesgo según la fórmula matemática de auditoría.
   */
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  evaluateInMemory(globalContext) {
    const { auth } = globalContext;
    Logger.log("========== INICIO DIAGNÓSTICO ID-180 (DOMAIN VERIFICATION) ==========");

    const authService = auth || new AuthService();
    const adminEmail = authService.getCurrentUserEmail();
    let authHeader = null;

    try {
      // Alcance (Scope) específico para la lectura de dominios en la Directory API
      authHeader = authService.getPrivilegedAuthHeader(adminEmail, [
        "https://www.googleapis.com/auth/admin.directory.domain.readonly"
      ]);
    } catch (e) {
      Logger.log(`[ID-180 - WARN] No se pudo obtener el token DWD: ${e.message}. Usando token interactivo.`);
      authHeader = authService.getAuthHeader();
    }

    const options = {
      method: "get",
      headers: authHeader,
      muteHttpExceptions: true
    };

    // Endpoint oficial v1 de la Directory API para listar dominios (No usamos APIs beta)
    const url = `https://admin.googleapis.com/admin/directory/v1/customer/${this.customerId}/domains`;
    
    let totalDomains = 0;
    const verifiedDomains = [];
    const unverifiedDomains = [];

    try {
      Logger.log(`[ID-180] Consultando el estado de verificación DNS de los dominios...`);
      const response = this.fetchWithBackoff(url, options);
      const code = response.getResponseCode();
      const text = response.getContentText();
      
      if (code === 200) {
        const json = JSON.parse(text);
        const domains = json.domains || [];
        totalDomains = domains.length;
        
        // Registro del HTTP 200 en los logs, tal cual solicitaste para ganar visibilidad
        Logger.log(`[ID-180 - API] Respondió con HTTP 200 para Domains API. Dominios analizados: ${totalDomains}`);
        
        domains.forEach(d => {
          // La API suele mapearlo en el atributo booleano "verified"
          const isVerified = d.verified === true || d.isVerified === true;
          
          if (isVerified) {
            verifiedDomains.push(d.domainName);
          } else {
            unverifiedDomains.push(d.domainName);
          }
        });
      } else {
        Logger.log(`[ID-180 - WARN] HTTP ${code} al consultar dominios. Detalle de Google: ${text}`);
      }
    } catch (err) {
      Logger.log(`[ID-180 - ERROR] Excepción al consultar dominios: ${err.message}`);
    }

    let valorPrincipal, comentario180, riesgo180;

    // RESPUESTA CORTA Y CONCISA
    if (totalDomains === 0) {
      valorPrincipal = "Desconocido";
      riesgo180 = "Medio";
      comentario180 = "No se pudieron recuperar los dominios asociados a la cuenta. Verifique los permisos de lectura de la Directory API.";
    } else if (unverifiedDomains.length === 0) {
      valorPrincipal = "Habilitado";
      riesgo180 = "Bajo";
      comentario180 = `Se analizaron ${totalDomains} dominio(s) en la cuenta y todos se encuentran correctamente verificados mediante registros DNS (TXT/CNAME).`;
    } else {
      valorPrincipal = "Deshabilitado";
      riesgo180 = "Alto";
      comentario180 = `Se encontraron ${unverifiedDomains.length} dominio(s) sin verificar (Ej: ${unverifiedDomains.slice(0, 3).join(", ")}). Esto representa un riesgo sistémico ya que la recuperación de credenciales y las comunicaciones esenciales operan bajo un estado degradado.`;
    }

    Logger.log(`[ID-180] Diagnóstico Terminado. Valor Principal: ${valorPrincipal} | Riesgo: ${riesgo180} | Dominios sin verificar: ${unverifiedDomains.length}`);
    Logger.log("========== FIN DIAGNÓSTICO ID-180 ==========");

    return {
      name: this.name,
      valorPrincipal: valorPrincipal,
      comentario180: comentario180,
      riesgo180: riesgo180,
      score180: this.calcularScoreDeRiesgo(riesgo180)
    };
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR",
      comentario180: `Ocurrió un error inesperado al procesar la validación: ${msg}`,
      riesgo180: "Medio",
      score180: 2
    };
  }
}