using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SegRedes.JWT.Servico.Model;

namespace SegRedes.JWT.Servico.Controllers
{
    [ApiController]
    [Authorize]
    [Route("api/servico")]
    public class ServicoController : ControllerBase
    {
        public ServicoController()
        {
        }

        [HttpGet]
        public ServicoResponse Get()
        {
            return new ServicoResponse()
            {
                Message = "Conteúdo"
            };                
        }
    }
}
